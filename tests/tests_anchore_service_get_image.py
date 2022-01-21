import unittest

from pydantic import ValidationError

from anchore.contants import NOT_FOUND_STATUS_CODE, SUCESS_STATUS_CODE, UNAUTHORIZED_STATUS_CODE
from anchore.models import AnchoreResponseOk, AnchoreResponseError
from anchore.service import AnchoreService
from tests.tests_anchore_service import TestAnchoreService


class TestAnchoreServiceGetImage(TestAnchoreService):

    def tests_get_image_existing(self):
        result = self.anchore_service.get_image(self.existing_tag_no_base)
        self.assertTrue(isinstance(result, AnchoreResponseOk))
        self.assertTrue(result.status_code == SUCESS_STATUS_CODE)

    def tests_get_image_non_existing(self):
        result = self.anchore_service.get_image(self.non_existing_tag)
        self.assertTrue(isinstance(result, AnchoreResponseError))
        self.assertTrue(result.status_code == NOT_FOUND_STATUS_CODE)

    def tests_get_image_empty_string(self):
        with self.assertRaises(ValidationError):
            self.anchore_service.get_image(self.empty_string)

    def tests_get_image_malformed_tag(self):
        with self.assertRaises(ValidationError):
            self.anchore_service.get_image(self.malformed_tag)

    def tests_get_image_bad_creds(self):
        url = "https://anchore-engine.corp.twilio.com"
        fake_user = "fake_user"
        fake_password = "fake_password"
        anchore_service = AnchoreService(url, fake_user, fake_password)
        result = anchore_service.get_image(self.existing_tag_no_base)
        self.assertTrue(isinstance(result, AnchoreResponseError))
        self.assertTrue(result.status_code == UNAUTHORIZED_STATUS_CODE)

    def tests_get_image_by_digest_existing(self):
        result = self.anchore_service.get_image_by_digest(self.existing_digest_no_base)
        self.assertTrue(isinstance(result, AnchoreResponseOk))
        self.assertTrue(result.status_code == SUCESS_STATUS_CODE)

    def tests_get_image_by_digest_non_existing(self):
        result = self.anchore_service.get_image_by_digest(self.non_existing_digest)
        self.assertTrue(isinstance(result, AnchoreResponseError))
        self.assertTrue(result.status_code == NOT_FOUND_STATUS_CODE)

    def tests_get_image_by_digest_empty_string(self):
        with self.assertRaises(ValidationError):
            self.anchore_service.get_image_by_digest(self.empty_string)

    def tests_get_image_by_digest_malformed_digest(self):
        with self.assertRaises(ValidationError):
            self.anchore_service.get_image_by_digest(self.malformed_digest)


if __name__ == "__main__":
    unittest.main()
