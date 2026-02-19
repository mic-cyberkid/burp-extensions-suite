import math

def calculate_shannon_entropy(data):
    """
    Calculates Shannon entropy of a string.
    """
    if not data:
        return 0
    entropy = 0
    # Handle both string and bytes for Jython compatibility
    length = len(data)

    # Character frequency map
    freq = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1

    for char in freq:
        p_x = float(freq[char]) / length
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def is_weak_token(token, threshold=3.5):
    """
    Returns True if the token entropy is below the threshold.
    """
    # Tokens shorter than 5 chars are generally weak regardless of entropy
    if len(token) < 5:
        return True
    return calculate_shannon_entropy(token) < threshold
