import unittest

from anchore.contants import SUCESS_STATUS_CODE
from anchore.models import AnchoreResponseOk
from tests.tests_anchore_service import TestAnchoreService


class TestAnchoreServiceAddImage(TestAnchoreService):

    def tests_add_image(self):
        result = self.anchore_service.add_image(self.new_image_to_add)
        self.assertTrue(isinstance(result, AnchoreResponseOk))
        self.assertTrue(result.status_code == SUCESS_STATUS_CODE)

    def tests_add_image_force(self):
        result = self.anchore_service.add_image(self.new_image_to_add, True)
        self.assertTrue(isinstance(result, AnchoreResponseOk))
        self.assertTrue(result.status_code == SUCESS_STATUS_CODE)


if __name__ == "__main__":
    unittest.main()
