import unittest

from anchore.contants import NOT_FOUND_STATUS_CODE, SUCESS_STATUS_CODE
from anchore.models import AnchoreResponseOk, AnchoreResponseError
from tests.tests_anchore_service import TestAnchoreService


class TestAnchoreServiceGetBaseImage(TestAnchoreService):

    def tests_get_base_image_digest_existing_digest_with_base(self):
        result = self.anchore_service.get_base_image_digest(self.digest_with_base_vulns1)
        self.assertTrue(isinstance(result, AnchoreResponseOk))
        self.assertTrue(result.status_code == SUCESS_STATUS_CODE)
        self.assertTrue(result.result is not None)

    def tests_get_base_image_digest_existing_digest_without_base(self):
        result = self.anchore_service.get_base_image_digest(self.existing_digest_no_base)
        self.assertTrue(isinstance(result, AnchoreResponseOk))
        self.assertTrue(result.status_code == SUCESS_STATUS_CODE)
        self.assertTrue(result.result is None)

    def tests_get_base_image_digest_non_existing_digest(self):
        result = self.anchore_service.get_base_image_digest(self.non_existing_digest)
        self.assertTrue(isinstance(result, AnchoreResponseError))
        self.assertTrue(result.status_code == NOT_FOUND_STATUS_CODE)


if __name__ == "__main__":
    unittest.main()
