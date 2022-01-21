import unittest

from anchore.contants import SUCESS_STATUS_CODE
from anchore.models import AnchoreResponseOk
from tests.tests_anchore_service import TestAnchoreService


class TestAnchoreServiceGetInventory(TestAnchoreService):

    def tests_get_inventory(self):
        result = self.anchore_service.get_inventory()
        self.assertTrue(isinstance(result, AnchoreResponseOk))
        self.assertTrue(result.status_code == SUCESS_STATUS_CODE)

    def tests_get_inventory_grouped(self):
        result = self.anchore_service.get_inventory(True)
        self.assertTrue(isinstance(result, AnchoreResponseOk))
        self.assertTrue(result.status_code == SUCESS_STATUS_CODE)


if __name__ == "__main__":
    unittest.main()
