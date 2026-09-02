"""
Core Data Model & Persistent NotebookStore for Fieldbook.
"""

import os
import json
import uuid
import time
import shutil
import logging
import threading
from datetime import datetime

logger = logging.getLogger("Fieldbook.Notebook")

ENTRY_TYPES = [
    "NOTE",
    "OBSERVATION",
    "HYPOTHESIS",
    "TEST_RESULT",
    "EVIDENCE",
    "TODO"
]

DEFAULT_ENTRY_TYPE = "NOTE"

try:
    from datetime import timezone
    def current_iso_timestamp():
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
except ImportError:
    def current_iso_timestamp():
        return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

class NotebookEntry(object):
    """
    Represents a single research note in Fieldbook.
    """
    def __init__(self, entry_id=None, entry_type="NOTE", text="", created_at=None,
                 updated_at=None, tags=None, target="", linked_requests=None,
                 linked_note_ids=None, pinned=False):
        self.id = entry_id or str(uuid.uuid4())
        self.entry_type = entry_type if entry_type in ENTRY_TYPES else DEFAULT_ENTRY_TYPE
        self.text = text or ""
        now = current_iso_timestamp()
        self.created_at = created_at or now
        self.updated_at = updated_at or now
        self.tags = list(tags) if tags else []
        self.target = target or ""
        self.linked_requests = list(linked_requests) if linked_requests else []
        self.linked_note_ids = list(linked_note_ids) if linked_note_ids else []
        self.pinned = bool(pinned)

    def update(self, entry_type=None, text=None, tags=None, target=None,
               linked_requests=None, linked_note_ids=None, pinned=None):
        if entry_type is not None and entry_type in ENTRY_TYPES:
            self.entry_type = entry_type
        if text is not None:
            self.text = text
        if tags is not None:
            self.tags = list(tags)
        if target is not None:
            self.target = target
        if linked_requests is not None:
            self.linked_requests = list(linked_requests)
        if linked_note_ids is not None:
            self.linked_note_ids = list(linked_note_ids)
        if pinned is not None:
            self.pinned = bool(pinned)
        self.updated_at = current_iso_timestamp()

    def to_dict(self):
        return {
            "id": self.id,
            "entry_type": self.entry_type,
            "text": self.text,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "tags": self.tags,
            "target": self.target,
            "linked_requests": self.linked_requests,
            "linked_note_ids": self.linked_note_ids,
            "pinned": self.pinned
        }

    @classmethod
    def from_dict(cls, data):
        if not isinstance(data, dict):
            raise ValueError("Invalid entry data format")

        # Helper to ensure string items in lists (Jython unicode handling)
        tags_raw = data.get("tags", [])
        tags = [str(t) for t in tags_raw] if isinstance(tags_raw, list) else []

        linked_reqs = data.get("linked_requests", [])
        if not isinstance(linked_reqs, list):
            linked_reqs = []

        linked_notes_raw = data.get("linked_note_ids", [])
        linked_note_ids = [str(n) for n in linked_notes_raw] if isinstance(linked_notes_raw, list) else []

        return cls(
            entry_id=str(data.get("id", str(uuid.uuid4()))),
            entry_type=str(data.get("entry_type", DEFAULT_ENTRY_TYPE)),
            text=str(data.get("text", "")),
            created_at=str(data.get("created_at", current_iso_timestamp())),
            updated_at=str(data.get("updated_at", current_iso_timestamp())),
            tags=tags,
            target=str(data.get("target", "")),
            linked_requests=linked_reqs,
            linked_note_ids=linked_note_ids,
            pinned=bool(data.get("pinned", False))
        )


class NotebookStore(object):
    """
    Thread-safe notebook persistence and query manager.
    Stores entries in a single JSON file on disk using atomic writes.
    """
    def __init__(self, filepath=None):
        if not filepath:
            filepath = os.path.expanduser("~/.fieldbook/notebook.json")
        self.filepath = os.path.abspath(filepath)
        self.lock = threading.Lock()
        self.entries = {}  # id -> NotebookEntry
        self.corrupt_warning = None
        self.last_used_entry_type = DEFAULT_ENTRY_TYPE

        self.load()

    def _ensure_dir(self):
        dirname = os.path.dirname(self.filepath)
        if dirname and not os.path.exists(dirname):
            try:
                os.makedirs(dirname)
            except OSError as e:
                logger.error("Failed to create directory %s: %s", dirname, e)

    def load(self):
        """Loads entries from JSON file on disk. Recovers on corruption."""
        with self.lock:
            self.entries = {}
            self.corrupt_warning = None
            if not os.path.exists(self.filepath):
                return

            try:
                with open(self.filepath, "r") as f:
                    content = f.read()
                if not content.strip():
                    return
                data = json.loads(content)
                if isinstance(data, dict) and "entries" in data:
                    raw_entries = data.get("entries", [])
                    self.last_used_entry_type = data.get("last_used_entry_type", DEFAULT_ENTRY_TYPE)
                elif isinstance(data, list):
                    raw_entries = data
                else:
                    raise ValueError("Unrecognized notebook format")

                for item in raw_entries:
                    try:
                        entry = NotebookEntry.from_dict(item)
                        self.entries[entry.id] = entry
                    except Exception as ex:
                        logger.warning("Skipping malformed entry item: %s", ex)

            except Exception as e:
                err_msg = "Corrupted notebook file detected at %s: %s" % (self.filepath, str(e))
                logger.error(err_msg)
                self.corrupt_warning = err_msg
                # Backup corrupt file
                timestamp = int(time.time())
                backup_path = "%s.corrupt.%d" % (self.filepath, timestamp)
                try:
                    shutil.copy2(self.filepath, backup_path)
                    logger.info("Corrupted notebook backed up to %s", backup_path)
                except Exception as backup_err:
                    logger.error("Failed to back up corrupted notebook: %s", backup_err)

                # Start fresh
                self.entries = {}

    def save(self):
        """Saves notebook state atomically to JSON file."""
        with self.lock:
            self._ensure_dir()
            data = {
                "version": 1,
                "last_used_entry_type": self.last_used_entry_type,
                "entries": [entry.to_dict() for entry in self.entries.values()]
            }
            content = json.dumps(data, indent=2, ensure_ascii=False)

            tmp_path = self.filepath + ".tmp." + str(uuid.uuid4())[:8]
            try:
                with open(tmp_path, "wb") as f:
                    if hasattr(content, "encode"):
                        f.write(content.encode("utf-8"))
                    else:
                        f.write(content)
                    f.flush()
                    os.fsync(f.fileno())

                # Atomic swap
                if hasattr(os, "replace"):
                    os.replace(tmp_path, self.filepath)
                else:
                    if os.path.exists(self.filepath):
                        os.remove(self.filepath)
                    os.rename(tmp_path, self.filepath)
            except Exception as e:
                logger.error("Failed to save notebook atomically: %s", e)
                if os.path.exists(tmp_path):
                    try:
                        os.remove(tmp_path)
                    except Exception:
                        pass
                raise e

    def add_entry(self, entry, save=True):
        with self.lock:
            self.entries[entry.id] = entry
            self.last_used_entry_type = entry.entry_type
        if save:
            self.save()

    def create_entry(self, entry_type="NOTE", text="", tags=None, target="",
                     linked_requests=None, linked_note_ids=None, pinned=False, save=True):
        entry = NotebookEntry(
            entry_type=entry_type,
            text=text,
            tags=tags,
            target=target,
            linked_requests=linked_requests,
            linked_note_ids=linked_note_ids,
            pinned=pinned
        )
        self.add_entry(entry, save=save)
        return entry

    def get_entry(self, entry_id):
        with self.lock:
            return self.entries.get(entry_id)

    def update_entry(self, entry_id, **kwargs):
        save = kwargs.pop("save", True)
        with self.lock:
            entry = self.entries.get(entry_id)
            if entry:
                entry.update(**kwargs)
                if "entry_type" in kwargs:
                    self.last_used_entry_type = kwargs["entry_type"]
        if entry and save:
            self.save()
        return entry

    def delete_entry(self, entry_id, save=True):
        with self.lock:
            existed = entry_id in self.entries
            if existed:
                del self.entries[entry_id]
        if existed and save:
            self.save()
        return existed

    def get_all_entries(self):
        with self.lock:
            return list(self.entries.values())

    def get_all_tags(self):
        with self.lock:
            tags = set()
            for entry in self.entries.values():
                tags.update(entry.tags)
            return sorted(list(tags))

    def get_all_targets(self):
        with self.lock:
            targets = set()
            for entry in self.entries.values():
                if entry.target and entry.target.strip():
                    targets.add(entry.target.strip())
            return sorted(list(targets))

    def get_backlinks(self, target_entry_id):
        """
        Returns a list of entries that reference target_entry_id either in
        their linked_note_ids or directly in text.
        """
        with self.lock:
            backlinks = []
            target_id_str = str(target_entry_id)
            for entry in self.entries.values():
                if entry.id == target_id_str:
                    continue
                if target_id_str in entry.linked_note_ids:
                    backlinks.append(entry)
                elif target_id_str in entry.text:
                    backlinks.append(entry)
            return backlinks

    def search_and_filter(self, query=None, entry_type=None, target=None,
                          tag=None, pinned_only=False):
        """
        Filters entries based on search text, entry_type, target, tag, pinned_only.
        Returns results sorted with pinned entries first, then updated_at descending.
        """
        with self.lock:
            results = list(self.entries.values())

        if pinned_only:
            results = [e for e in results if e.pinned]

        if entry_type and entry_type != "ALL":
            results = [e for e in results if e.entry_type.upper() == entry_type.upper()]

        if target and target != "ALL":
            target_lower = target.lower()
            results = [e for e in results if target_lower == e.target.lower()]

        if tag and tag != "ALL":
            tag_lower = tag.lower()
            results = [e for e in results if any(tag_lower == t.lower() for t in e.tags)]

        if query and query.strip():
            q = query.strip().lower()
            filtered = []
            for e in results:
                # Match in text, target, tags, entry_type, or linked requests
                if q in e.text.lower():
                    filtered.append(e)
                elif q in e.target.lower():
                    filtered.append(e)
                elif any(q in t.lower() for t in e.tags):
                    filtered.append(e)
                elif q in e.entry_type.lower():
                    filtered.append(e)
                else:
                    # Match in linked requests (label, url, host, method)
                    req_match = False
                    for req in e.linked_requests:
                        if isinstance(req, dict):
                            label = str(req.get("label", "")).lower()
                            url = str(req.get("url", "")).lower()
                            host = str(req.get("host", "")).lower()
                            method = str(req.get("method", "")).lower()
                            if q in label or q in url or q in host or q in method:
                                req_match = True
                                break
                    if req_match:
                        filtered.append(e)
            results = filtered

        # Sort: pinned first, then updated_at descending
        results.sort(key=lambda e: (not e.pinned, e.updated_at), reverse=False)
        # Note: (not e.pinned) puts True (pinned) before False (unpinned).
        # For updated_at, we want descending, so let's adjust key:
        results.sort(key=lambda e: (0 if e.pinned else 1, e.updated_at), reverse=False)
        # Sort by updated_at descending within pinned / unpinned
        pinned_entries = [e for e in results if e.pinned]
        unpinned_entries = [e for e in results if not e.pinned]
        pinned_entries.sort(key=lambda e: e.updated_at, reverse=True)
        unpinned_entries.sort(key=lambda e: e.updated_at, reverse=True)

        return pinned_entries + unpinned_entries
