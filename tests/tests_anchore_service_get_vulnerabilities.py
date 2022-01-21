import unittest

from pydantic import ValidationError

from anchore.contants import NOT_FOUND_STATUS_CODE, SUCESS_STATUS_CODE, ERROR_STATUS_CODE
from anchore.models import AnchoreResponseOk, AnchoreResponseError, VulnerabilitySeverity, VulnerabilityType
from tests.tests_anchore_service import TestAnchoreService


class TestAnchoreServiceGetVulnerabilities(TestAnchoreService):

    def tests_get_vulnerabilities_by_digest_existing_digest_with_base_and_vulns1(self):
        result = self.anchore_service.get_vulnerabilities_by_digest(self.digest_with_base_vulns1, base_image_digest=self.base_image_digest1)
        self.assertTrue(isinstance(result, AnchoreResponseOk))
        self.assertTrue(result.status_code == SUCESS_STATUS_CODE)

    def tests_get_vulnerabilities_by_digest_existing_digest_with_base_and_vulns2(self):
        result = self.anchore_service.get_vulnerabilities_by_digest(self.digest_with_base_vulns2, base_image_digest=self.base_image_digest2)
        self.assertTrue(isinstance(result, AnchoreResponseOk))
        self.assertTrue(result.status_code == SUCESS_STATUS_CODE)

    def tests_get_vulnerabilities_by_digest_non_existing_digest(self):
        result = self.anchore_service.get_vulnerabilities_by_digest(self.non_existing_digest)
        self.assertTrue(isinstance(result, AnchoreResponseError))
        self.assertTrue(result.status_code == NOT_FOUND_STATUS_CODE)

    def tests_get_vulnerabilities_by_digest_existing_digest_with_non_existing_base_vulns1(self):
        result = self.anchore_service.get_vulnerabilities_by_digest(self.digest_with_base_vulns1, base_image_digest=self.non_existing_digest)
        self.assertTrue(isinstance(result, AnchoreResponseError))
        self.assertTrue(result.status_code == ERROR_STATUS_CODE)

    def tests_get_vulnerabilities_by_digest_existing_digest_with_malformed_base_vulns1(self):
        with self.assertRaises(ValidationError):
            self.anchore_service.get_vulnerabilities_by_digest(self.digest_with_base_vulns1, base_image_digest=self.malformed_digest)

    def tests_get_vulnerabilities_by_digest_existing_digest_with_base_and_vulns1_only_medium(self):
        medium_list = [VulnerabilitySeverity.medium]
        result = self.anchore_service.get_vulnerabilities_by_digest(self.digest_with_base_vulns1, base_image_digest=self.base_image_digest1, severity_list=medium_list)
        self.assertTrue(isinstance(result, AnchoreResponseOk))
        self.assertTrue(result.status_code == SUCESS_STATUS_CODE)

    def tests_get_vulnerabilities_by_digest_existing_digest_with_base_and_vulns1_only_high(self):
        high_list = [VulnerabilitySeverity.high]
        result = self.anchore_service.get_vulnerabilities_by_digest(self.digest_with_base_vulns1, base_image_digest=self.base_image_digest1, severity_list=high_list)
        self.assertTrue(isinstance(result, AnchoreResponseOk))
        self.assertTrue(result.status_code == SUCESS_STATUS_CODE)

    def tests_get_vulnerabilities_by_digest_existing_digest_with_base_and_vulns1_low_high(self):
        lh_list = [VulnerabilitySeverity.high, VulnerabilitySeverity.low]
        result = self.anchore_service.get_vulnerabilities_by_digest(self.digest_with_base_vulns1, base_image_digest=self.base_image_digest1, severity_list=lh_list)
        self.assertTrue(isinstance(result, AnchoreResponseOk))
        self.assertTrue(result.status_code == SUCESS_STATUS_CODE)

    def tests_get_vulnerabilities_by_digest_existing_digest_with_base_and_vulns1_only_os_type(self):
        os_type = VulnerabilityType.os
        result = self.anchore_service.get_vulnerabilities_by_digest(self.digest_with_base_vulns1, base_image_digest=self.base_image_digest1, vtype=os_type)
        self.assertTrue(isinstance(result, AnchoreResponseOk))
        self.assertTrue(result.status_code == SUCESS_STATUS_CODE)

    def tests_get_vulnerabilities_by_digest_existing_digest_with_base_and_vulns1_all_type_with_fix(self):
        all_type = VulnerabilityType.all
        result = self.anchore_service.get_vulnerabilities_by_digest(self.digest_with_base_vulns1, base_image_digest=self.base_image_digest1, fix_required=True,
                                                                    vtype=all_type)
        self.assertTrue(isinstance(result, AnchoreResponseOk))
        self.assertTrue(result.status_code == SUCESS_STATUS_CODE)

    def tests_get_vulnerabilities_by_id(self):
        result = self.anchore_service.get_vulnerabilities_by_id(self.existing_id_no_base)
        self.assertTrue(isinstance(result, AnchoreResponseOk))
        self.assertTrue(result.status_code == SUCESS_STATUS_CODE)

    def tests_get_vulnerabilities_by_id_compare_with_digest(self):
        result_id = self.anchore_service.get_vulnerabilities_by_id(self.existing_id_no_base)
        self.assertTrue(isinstance(result_id, AnchoreResponseOk))
        self.assertTrue(result_id.status_code == SUCESS_STATUS_CODE)

        result_digest = self.anchore_service.get_vulnerabilities_by_digest(self.existing_digest_no_base)
        self.assertTrue(isinstance(result_digest, AnchoreResponseOk))
        self.assertTrue(result_digest.status_code == SUCESS_STATUS_CODE)

        self.assertTrue(len(result_id.result) == len(result_digest.result))


if __name__ == "__main__":
    unittest.main()
