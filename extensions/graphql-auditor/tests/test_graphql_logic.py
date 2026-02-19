import unittest
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))

from GraphQLLogic import GraphQLLogic

class TestGraphQLLogic(unittest.TestCase):
    def setUp(self):
        self.logic = GraphQLLogic()

    def test_is_graphql_request(self):
        self.assertTrue(self.logic.is_graphql_request("http://test.com/graphql", ""))
        self.assertTrue(self.logic.is_graphql_request("http://test.com/api", '{"query": "{user{id}}"}'))
        self.assertFalse(self.logic.is_graphql_request("http://test.com/api", '{"id": 1}'))

    def test_introspection_detect(self):
        body = '{"data": {"__schema": {"queryType": {"name": "Query"}}}}'
        findings = self.logic.analyze_response("http://test.com/graphql", body)
        self.assertTrue(any("Introspection Enabled" in f['name'] for f in findings))

    def test_sensitive_data_exposure(self):
        body = '{"data": {"user": {"email": "admin@test.com", "password": "hash"}}}'
        findings = self.logic.analyze_response("http://test.com/graphql", body)
        self.assertTrue(any("Sensitive Data Exposure" in f['name'] for f in findings))

if __name__ == '__main__':
    unittest.main()
