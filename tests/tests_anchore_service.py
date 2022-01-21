import os
import unittest

from anchore.service import AnchoreService
from tests import load_env_variables


class TestAnchoreService(unittest.TestCase):

    def setUp(self):
        load_env_variables()
        self.__init_images_variables_values()
        url = os.getenv("ANCHORE_ENGINE_URL")
        user = os.getenv("ANCHORE_ENGINE_USER")
        password = os.getenv("ANCHORE_ENGINE_PASSWORD")
        self.anchore_service = AnchoreService(url, user, password)

    def __init_images_variables_values(self):
        #: Create the .env file in the tests folder and add the right values found in the Anchore database to run the tests
        self.empty_string = ""
        self.malformed_tag = "@@dsdsds#d"
        #: Fake tag that does not exists in the Anchore database
        self.non_existing_tag = os.getenv("non_existing_tag")
        #: Fake digest that does not exists in the Anchore database (right format)
        self.non_existing_digest = os.getenv("non_existing_digest")
        #: Fake digest with wrong format
        self.malformed_digest = os.getenv("malformed_digest")
        #: Right fulltag that does not exists in the Anchore DB and can be added
        self.new_image_to_add = os.getenv("new_image_to_add")
        #: Image tag that exists in the Anchore database but it does not have a known base image
        self.existing_tag_no_base = os.getenv("existing_tag_no_base")
        #: Image digest that exists in the Anchore database but it does not have a known base image
        self.existing_digest_no_base = os.getenv("existing_digest_no_base")
        #: Image Id that exists in the Anchore database but it does not have a known base image
        self.existing_id_no_base = os.getenv("existing_id_no_base")
        #: Image tag that exists in the Anchore database having vulnerabilities (1)
        self.tag_vulns1 = os.getenv("tag_vulns1")
        #: Image digest that exists in the Anchore database having vulnerabilities and a known base image (1)
        self.digest_with_base_vulns1 = os.getenv("digest_with_base_vulns1")
        #: The digest of the base image (1)
        self.base_image_digest1 = os.getenv("base_image_digest1")
        #: Image id that exists in the Anchore database having vulnerabilities and a known base image (1)
        self.existing_id_vulns1 = os.getenv("existing_id_vulns1")
        #: Image tag that exists in the Anchore database having vulnerabilities (2)
        self.tag_vulns2 = os.getenv("tag_vulns2")
        #: Image digest that exists in the Anchore database having vulnerabilities and a known base image (2)
        self.digest_with_base_vulns2 = os.getenv("digest_with_base_vulns2")
        #: The digest of the base image (1)
        self.base_image_digest2 = os.getenv("base_image_digest2")
        #: Image id that exists in the Anchore database having vulnerabilities and a known base image (2)
        self.existing_id_vulns2 = os.getenv("existing_id_vulns2")
        #: Policy ID
        self.policy_id = os.getenv("policy_id")


if __name__ == "__main__":
    unittest.main()
