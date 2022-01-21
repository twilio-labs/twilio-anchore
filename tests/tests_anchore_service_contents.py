import unittest

from anchore.contants import SUCESS_STATUS_CODE
from anchore.models import AnchoreResponseOk
from tests.tests_anchore_service import TestAnchoreService


class TestAnchoreServiceGetInventory(TestAnchoreService):

    def test_get_image_content_types(self):
        result = self.anchore_service.get_image_content_types(self.digest_with_base_vulns1)
        self.assertTrue(isinstance(result, AnchoreResponseOk))
        self.assertTrue(result.status_code == SUCESS_STATUS_CODE)

    def test_get_image_contents_by_type_os(self):
        content_type = "os"
        result = self.anchore_service.get_image_contents_by_type(self.digest_with_base_vulns1, content_type)
        self.assertTrue(isinstance(result, AnchoreResponseOk))
        self.assertTrue(result.status_code == SUCESS_STATUS_CODE)

    def test_get_image_contents_by_type_java(self):
        content_type = "java"
        result = self.anchore_service.get_image_contents_by_type(self.digest_with_base_vulns1, content_type)
        self.assertTrue(isinstance(result, AnchoreResponseOk))
        self.assertTrue(result.status_code == SUCESS_STATUS_CODE)

    def test_get_image_contents_by_type_malware(self):
        content_type = "malware"
        result = self.anchore_service.get_image_contents_by_type(self.digest_with_base_vulns1, content_type)
        self.assertTrue(isinstance(result, AnchoreResponseOk))
        self.assertTrue(result.status_code == SUCESS_STATUS_CODE)

    def test_get_image_malware_findings(self):
        result = self.anchore_service.get_image_malware_findings(self.digest_with_base_vulns1)
        self.assertTrue(isinstance(result, AnchoreResponseOk))
        self.assertTrue(result.status_code == SUCESS_STATUS_CODE)


if __name__ == "__main__":
    unittest.main()
