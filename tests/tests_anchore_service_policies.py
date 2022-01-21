import unittest

from anchore.contants import SUCESS_STATUS_CODE, NOT_FOUND_STATUS_CODE
from anchore.models import AnchoreResponseOk, AnchoreResponseError
from tests.tests_anchore_service import TestAnchoreService


class TestAnchoreServiceGetInventory(TestAnchoreService):

    def tests_get_policies_ids(self):
        result = self.anchore_service.get_policies_ids()
        self.assertTrue(isinstance(result, AnchoreResponseOk))
        self.assertTrue(result.status_code == SUCESS_STATUS_CODE)

    def tests_evaluate_policy_with_tag(self):
        result = self.anchore_service.evaluate_policy(self.digest_with_base_vulns1, self.tag_vulns1, self.policy_id)
        self.assertTrue(isinstance(result, AnchoreResponseOk))
        self.assertTrue(result.status_code == SUCESS_STATUS_CODE)
        self.assertTrue(result.result)

    def tests_evaluate_policy_non_existing_digest(self):
        result = self.anchore_service.evaluate_policy(self.non_existing_digest, self.tag_vulns1, self.policy_id)
        self.assertTrue(isinstance(result, AnchoreResponseError))
        self.assertTrue(result.status_code == NOT_FOUND_STATUS_CODE)

    def tests_evaluate_policy_non_existing_policy(self):
        result = self.anchore_service.evaluate_policy(self.digest_with_base_vulns1, self.tag_vulns1, "fake_policy_id")
        self.assertTrue(isinstance(result, AnchoreResponseError))
        self.assertTrue(result.status_code == NOT_FOUND_STATUS_CODE)


if __name__ == "__main__":
    unittest.main()
