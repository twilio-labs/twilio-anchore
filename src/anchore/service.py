import json
import logging
from typing import List

from pydantic import AnyHttpUrl, validate_arguments, constr
from requests import Response

from anchore.contants import SUCESS_STATUS_CODE, CONTAINER_IMAGE_FULLTAG_REGEX, IMAGES_REQUEST, \
    CONTAINER_IMAGE_DIGEST_REGEX, ENTERPRISE_ANCESTORS, IMAGES_REQUEST_DIGEST, ENTERPRISE_VULN_REQUEST_DIGEST_PARENT, VULN_REQUEST_DIGEST, \
    CONTAINER_IMAGE_ID_REGEX, VULN_REQUEST_ID, ENTERPRISE_INVENTORY, ADD_IMAGE_REQUEST, BASE_PATH, ENTERPRISE_BASE_PATH, POLICIES_IDS_REQUEST, POLICIES_CHECK, \
    IMAGE_CONTENTS, IMAGE_CONTENTS_BY_TYPE
from anchore.models import ContainerImage, AnchoreResponse, AnchoreServiceException, AnchoreResponseOk, AnchoreResponseError, \
    VulnerabilityType, VulnerabilitySeverity, Vulnerability, InventoryImage
from anchore import helper

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class AnchoreService:
    """Main class used to access the Anchore API
    :Example:

    .. code-block:: python

        >>> anchore_service = AnchoreService("https://analyzer.anchore.com", "anchoreuser", "password")

    :param host_url: Anchore Engine URL
    :type host_url: AnyHttpUrl
    :param user: Required user to connect to Anchore
    :type user: str
    :param password: Password of the user
    :type password: str
    :param base_path: Initial URL segment of the Anchore API
    :type base_path: str, optional
    :param enterprise_base_path: Initial URL segment of the Enterprise Anchore API
    :type enterprise_base_path: str, optional
    :param verify: Boolean value used to verify Anchore certificate
    :type verify: bool, optional
    """

    def __init__(self, host_url: AnyHttpUrl, user: str, password: str, base_path: str = BASE_PATH, enterprise_base_path: str = ENTERPRISE_BASE_PATH, verify: bool = True):
        self.__host_url = host_url
        self.__user = user
        self.__password = password
        self.__base_path = base_path
        self.__enterprise_base_path = enterprise_base_path
        self.__verify = verify

    ############################################
    # ANALYZE IMAGE
    ############################################
    @validate_arguments
    def add_image(self, fulltag: constr(regex=CONTAINER_IMAGE_FULLTAG_REGEX), force: bool = False) -> AnchoreResponse:
        """Submits a new image to be analyzed by Anchore.

        :param fulltag: Container image fulltag
        :type fulltag: str
        :param force: If true, the image will be added to the queue even if the image has been analyzed before
        :type force: bool, optional

        :raises AnchoreServiceException: Exception raised when an unexpected error occurs

        :return: Any subclass instance of :class:`src.models.anchore_models.AnchoreResponse` containing the status code.
            On a successful request a :class:`src.models.anchore_models.AnchoreResponseOk` instance is returned and the result will contain a
            :class:`src.models.anchore_models.ContainerImage` instance.
            On a non successful request a :class:`src.models.anchore_models.AnchoreResponseError` instance is returned containing the error message
        :rtype: AnchoreResponse
        """
        try:
            logger.info("Adding the container image %s to the Anchore database" % fulltag)
            request_url = self.__host_url + self.__base_path + ADD_IMAGE_REQUEST.format(force)
            response = helper.send_post_request_basic_auth(request_url, self.__user, self.__password, {"tag": fulltag}, self.__verify)
            return AnchoreService.__process_image_response_data(response)
        except Exception as exc:
            logger.error("Error while adding new image to the Anchore database: " + str(exc))
            raise AnchoreServiceException("Error while adding new image to the Anchore database: " + str(exc))

    @staticmethod
    def __process_image_response_data(response: Response) -> AnchoreResponse:
        status_code = response.status_code
        if status_code == SUCESS_STATUS_CODE:
            image = ContainerImage(**response.json()[0])
            return AnchoreResponseOk(status_code=status_code, result=image)
        else:
            error_message = AnchoreService.__get_error_message(response.text)
            return AnchoreResponseError(status_code=status_code, error_message=error_message)

    ############################################
    # GET IMAGE
    ############################################
    @validate_arguments
    def get_image(self, fulltag: constr(regex=CONTAINER_IMAGE_FULLTAG_REGEX)) -> AnchoreResponse:
        """Method used to get the information of a container image specified by its fulltag

        :param fulltag: Container image fulltag
        :type fulltag: str

        :raises AnchoreServiceException: Exception raised when an unexpected error occurs

        :return: Any subclass instance of :class:`src.models.anchore_models.AnchoreResponse` containing the status code.
            On a successful request a :class:`src.models.anchore_models.AnchoreResponseOk` instance is returned and the result will contain a
            :class:`src.models.anchore_models.ContainerImage` instance.
            On a non successful request a :class:`src.models.anchore_models.AnchoreResponseError` instance is returned containing the error message
        :rtype: AnchoreResponse
        """
        try:
            logger.info("Getting container image %s information from Anchore DB" % fulltag)
            request_url = self.__host_url + self.__base_path + IMAGES_REQUEST.format(fulltag)
            return self.__get_image_info(request_url)
        except Exception as exc:
            logger.error("Error while trying to get the container image information: " + str(exc))
            raise AnchoreServiceException("Error while trying to get the container image information: " + str(exc))

    @validate_arguments
    def get_image_by_digest(self, image_digest: constr(regex=CONTAINER_IMAGE_DIGEST_REGEX)) -> AnchoreResponse:
        """Method used to get the information of a container image specified by its digest value

        :param image_digest: Container image digest value
        :type image_digest: str

        :raises AnchoreServiceException: Exception raised when an unexpected error occurs

        :return: Any subclass instance of :class:`src.models.anchore_models.AnchoreResponse` containing the status code.
            On a successful request a :class:`src.models.anchore_models.AnchoreResponseOk` instance is returned and the result will contain a
            :class:`src.models.anchore_models.ContainerImage` instance.
            On a non successful request a :class:`src.models.anchore_models.AnchoreResponseError` instance is returned containing the error message
        :rtype: AnchoreResponse
        """
        try:
            logger.info("Getting container image information from Anchore DB by digest: %s" % image_digest)
            request_url = self.__host_url + self.__base_path + IMAGES_REQUEST_DIGEST.format(image_digest)
            return self.__get_image_info(request_url)
        except Exception as exc:
            logger.error("Error while trying to get the container image information: " + str(exc))
            raise AnchoreServiceException("Error while trying to get the container image information: " + str(exc))

    def __get_image_info(self, request_url: AnyHttpUrl) -> AnchoreResponse:
        response = helper.send_get_request_basic_auth(request_url, self.__user, self.__password, self.__verify)
        return AnchoreService.__process_image_response_data(response)

    ############################################
    # GET BASE IMAGE DIGEST
    ############################################
    @validate_arguments
    def get_base_image_digest(self, image_digest: constr(regex=CONTAINER_IMAGE_DIGEST_REGEX)) -> AnchoreResponse:
        """Method used to get the digest of the base image of the image specified by its digest.

        :param image_digest: Container image digest value
        :type image_digest: str

        :raises AnchoreServiceException: Exception raised when an unexpected error occurs

        :return: Any subclass instance of :class:`src.models.anchore_models.AnchoreResponse` containing the status code.
            On a successful request a :class:`src.models.anchore_models.AnchoreResponseOk` instance is returned and the result will contain the base image digest,
            or None if the specified contianer image does not have a known base image.
            On a non successful request a :class:`src.models.anchore_models.AnchoreResponseError` instance is returned containing the error message
        :rtype: AnchoreResponse
        """
        try:
            logger.info("Getting the base image digest of the container image with digest: %s" % image_digest)
            request_url = self.__host_url + self.__enterprise_base_path + ENTERPRISE_ANCESTORS.format(image_digest)
            response = helper.send_get_request_basic_auth(request_url, self.__user, self.__password, self.__verify)
            status_code = response.status_code
            if response.status_code == SUCESS_STATUS_CODE:
                base_image_digest = None
                if len(response.json()) > 0:
                    base_image_digest = response.json()[0]["imageDigest"]
                return AnchoreResponseOk(status_code=status_code, result=base_image_digest)
            else:
                error_message = AnchoreService.__get_error_message(response.text)
                return AnchoreResponseError(status_code=status_code, error_message=error_message)
        except Exception as exc:
            logger.exception("Error while trying to get the base image digest: " + str(exc))
            raise AnchoreServiceException("Error while trying to get the base image digest: " + str(exc))

    ############################################
    # GET VULNERABILITIES
    ############################################
    @validate_arguments
    def get_vulnerabilities_by_digest(self, image_digest: constr(regex=CONTAINER_IMAGE_DIGEST_REGEX), vtype: VulnerabilityType = VulnerabilityType.all,
                                      severity_list: List[VulnerabilitySeverity] = None, fix_required: bool = False,
                                      base_image_digest: constr(regex=CONTAINER_IMAGE_DIGEST_REGEX) = None) -> AnchoreResponse:
        """Method used to get the vulnerabilities of the image specified by its digest.

        :param image_digest: Container image digest value
        :type image_digest: str
        :param vtype: The type of vulnerabilities to be returned [os, non-os, all]
        :type vtype: VulnerabilityType, optional
        :param severity_list: Severities of the vulnerabilities to be returned
        :type severity_list: List of VulnerabilitySeverity, optional
        :param fix_required: If True only vulnerabilities with a known fix will be returned
        :type fix_required: bool, optional
        :param base_image_digest: Base image digest value. This is an Enterprise feature.
            If not None, information about whether the vulnerability is inherited from the base image or not is added
        :type base_image_digest: str, optional

        :raises AnchoreServiceException: Exception raised when an unexpected error occurs

        :return: Any subclass instance of :class:`src.models.anchore_models.AnchoreResponse` containing the status code.
            On a successful request a :class:`src.models.anchore_models.AnchoreResponseOk` instance is returned and the result will contain a
            list of :class:`src.models.anchore_models.Vulnerability` instances. The list can be empty if the container image does not have any vulnerability.
            On a non successful request a :class:`src.models.anchore_models.AnchoreResponseError` instance is returned containing the error message
        :rtype: AnchoreResponse
        """
        try:
            if base_image_digest is not None:
                request_url = self.__host_url + self.__enterprise_base_path + ENTERPRISE_VULN_REQUEST_DIGEST_PARENT.format(image_digest, vtype, base_image_digest)
            else:
                request_url = self.__host_url + self.__base_path + VULN_REQUEST_DIGEST.format(image_digest, vtype)
            return self.__get_vulnerabilities(request_url, severity_list, fix_required)
        except Exception as exc:
            logger.exception("Error while trying to get the list of vulnerabilities: " + str(exc))
            raise AnchoreServiceException("Error while trying to get the list of vulnerabilities: " + str(exc))

    @validate_arguments
    def get_vulnerabilities_by_id(self, image_id: constr(regex=CONTAINER_IMAGE_ID_REGEX), vtype: VulnerabilityType = VulnerabilityType.all,
                                  severity_list: List[VulnerabilitySeverity] = None, fix_required: bool = False) -> AnchoreResponse:
        """Method used to get the vulnerabilities of the image specified by its id.

        :param image_id: Container image id value
        :type image_id: str
        :param vtype: The type of vulnerabilities to be returned [os, non-os, all]
        :type vtype: VulnerabilityType, optional
        :param severity_list: Severities of the vulnerabilities to be returned
        :type severity_list: List of VulnerabilitySeverity, optional
        :param fix_required: If True only vulnerabilities with a known fix will be returned
        :type fix_required: bool, optional

        :raises AnchoreServiceException: Exception raised when an unexpected error occurs

        :return: Any subclass instance of :class:`src.models.anchore_models.AnchoreResponse` containing the status code.
            On a successful request a :class:`src.models.anchore_models.AnchoreResponseOk` instance is returned and the result will contain a
            list of :class:`src.models.anchore_models.Vulnerability` instances. The list can be empty if the container image does not have any vulnerability.
            On a non successful request a :class:`src.models.anchore_models.AnchoreResponseError` instance is returned containing the error message
        :rtype: AnchoreResponse
        """
        try:
            request_url = self.__host_url + self.__base_path + VULN_REQUEST_ID.format(image_id, vtype)
            return self.__get_vulnerabilities(request_url, severity_list, fix_required)
        except Exception as exc:
            logger.exception("Error while trying to get the list of vulnerabilities: " + str(exc))
            raise AnchoreServiceException("Error while trying to get the list of vulnerabilities: " + str(exc))

    def __get_vulnerabilities(self, request_url: AnyHttpUrl, severity_list: List[VulnerabilitySeverity] = None, fix_required: bool = False) -> AnchoreResponse:
        logger.info("Getting container image vulnerabilities information")
        response = helper.send_get_request_basic_auth(request_url, self.__user, self.__password, self.__verify)
        status_code = response.status_code
        if status_code == SUCESS_STATUS_CODE:
            vulns_list = response.json()["vulnerabilities"]
            vulnerabilities_list = AnchoreService.__get_vulns_list_from_json(vulns_list, severity_list, fix_required)
            return AnchoreResponseOk(status_code=status_code, result=vulnerabilities_list)
        else:
            error_message = AnchoreService.__get_error_message(response.text)
            return AnchoreResponseError(status_code=status_code, error_message=error_message)

    @staticmethod
    def __get_vulns_list_from_json(json_list: List[dict], severity_list: List[VulnerabilitySeverity] = None, fix_required: bool = False) -> List[Vulnerability]:
        result = []
        for json_item in json_list:
            vulnerability = Vulnerability(**json_item)
            meets_the_filters = AnchoreService.__vulnerability_meets_the_filters(vulnerability, severity_list, fix_required)
            if meets_the_filters:
                result.append(vulnerability)
        return result

    @staticmethod
    def __vulnerability_meets_the_filters(vulnerability: Vulnerability, severity_list: List[VulnerabilitySeverity] = None, fix_required: bool = False):
        filter_severity = False
        filter_fix = False
        if severity_list is not None and len(severity_list) > 0:
            if vulnerability.severity in severity_list:
                filter_severity = True
        else:
            filter_severity = True
        if not fix_required:
            filter_fix = True
        elif vulnerability.fix is not None:
            filter_fix = True
        return filter_severity and filter_fix

    ############################################
    # GET INVENTORY
    ############################################
    @validate_arguments
    def get_inventory(self, group_by_image: bool = False) -> AnchoreResponse:
        """Method used to get a list containing the container images of the inventory

        :param group_by_image: If true, the container images with the same digest are grouped and the information
            of the different contexts are added to the list of contexts.
            If false, each inventory entry is added to the inventory list.
        :type group_by_image: bool, optional

        :raises AnchoreServiceException: Exception raised when an unexpected error occurs

        :return: Any subclass instance of :class:`src.models.anchore_models.AnchoreResponse` containing the status code.
            On a successful request a :class:`src.models.anchore_models.AnchoreResponseOk` instance is returned and the result will contain a
            list of :class:`src.models.anchore_models.InventoryImage` instances.
            On a non successful request a :class:`src.models.anchore_models.AnchoreResponseError` instance is returned containing the error message
        :rtype: AnchoreResponse
        """
        try:
            logger.info("Getting the K8s Clusters inventory information")
            request_url = self.__host_url + self.__enterprise_base_path + ENTERPRISE_INVENTORY
            response = helper.send_get_request_basic_auth(request_url, self.__user, self.__password, self.__verify)
            status_code = response.status_code
            if response.status_code == SUCESS_STATUS_CODE:
                inventory_list = []
                if len(response.json()) > 0:
                    inventory_list = AnchoreService.__get_inventory_list_from_json(response.json(), group_by_image)
                return AnchoreResponseOk(status_code=status_code, result=inventory_list)
            else:
                error_message = AnchoreService.__get_error_message(response.text)
                return AnchoreResponseError(status_code=status_code, error_message=error_message)
        except Exception as exc:
            logger.exception("Error while trying to get the inventory information: " + str(exc))
            raise AnchoreServiceException("Error while trying to get the inventory information: " + str(exc))

    @staticmethod
    def __get_inventory_list_from_json(inventory_list: List[dict], group_by_image: bool) -> List[InventoryImage]:
        result = []
        for image_entry in inventory_list:
            inventory_entry = InventoryImage(**image_entry)
            if group_by_image:
                processed = AnchoreService.__image_already_processed(inventory_entry, result)
                if not processed:
                    result.append(inventory_entry)
            else:
                result.append(inventory_entry)
        return result

    @staticmethod
    def __image_already_processed(inventory_entry: InventoryImage, inventory_list: List[InventoryImage]):
        result = False
        if inventory_list is not None and len(inventory_list) > 0:
            for inventory in inventory_list:
                if inventory.digest == inventory_entry.digest:
                    inventory.context_list.extend(inventory_entry.context_list)
                    result = True
                    break
        return result

    @staticmethod
    def __get_error_message(response_text: str) -> str:
        try:
            error_json = json.loads(response_text)
            return error_json["message"]
        except Exception as exc:
            logger.error("Response error message is not a JSON: " + str(exc))
            return response_text

    ############################################
    # POLICIES
    ############################################
    @validate_arguments
    def get_policies_ids(self) -> AnchoreResponse:
        """Method used to get a list containing all the existing policies IDs

        :raises AnchoreServiceException: Exception raised when an unexpected error occurs

        :return: Any subclass instance of :class:`src.models.anchore_models.AnchoreResponse` containing the status code.
            On a successful request a :class:`src.models.anchore_models.AnchoreResponseOk` instance is returned and the result will contain the
            list of the different policies IDs.
            On a non successful request a :class:`src.models.anchore_models.AnchoreResponseError` instance is returned containing the error message
        :rtype: AnchoreResponse
        """
        try:
            logger.info("Getting Anchore Engine policies IDs")
            request_url = self.__host_url + self.__base_path + POLICIES_IDS_REQUEST
            response = helper.send_get_request_basic_auth(request_url, self.__user, self.__password, self.__verify)
            status_code = response.status_code
            if response.status_code == SUCESS_STATUS_CODE:
                policies_ids_list = []
                if len(response.json()) > 0:
                    policies_ids_list = AnchoreService.__get_policies_ids_list_from_json(response.json())
                return AnchoreResponseOk(status_code=status_code, result=policies_ids_list)
            else:
                error_message = AnchoreService.__get_error_message(response.text)
                return AnchoreResponseError(status_code=status_code, error_message=error_message)
        except Exception as exc:
            logger.exception("Error while trying to get the policies IDs: " + str(exc))
            raise AnchoreServiceException("Error while trying to get the policies IDs: " + str(exc))

    @staticmethod
    def __get_policies_ids_list_from_json(policies_response: List[dict]) -> List[str]:
        policies_ids_list = []
        for policy in policies_response:
            policy_id = policy["policyId"]
            policies_ids_list.append(policy_id)
        return policies_ids_list

    @validate_arguments
    def evaluate_policy(self, image_digest: constr(regex=CONTAINER_IMAGE_DIGEST_REGEX), fulltag: constr(regex=CONTAINER_IMAGE_FULLTAG_REGEX),
                        policy_id: str) -> AnchoreResponse:
        """Method used to check if the specified image passes the evaluation against the specified policy

        :param image_digest: Container image digest value
        :type image_digest: str
        :param fulltag: Container image fulltag
        :type fulltag: str
        :param policy_id: Id of the policy
        :type policy_id: str

        :raises AnchoreServiceException: Exception raised when an unexpected error occurs

        :return: Any subclass instance of :class:`src.models.anchore_models.AnchoreResponse` containing the status code.
            On a successful request a :class:`src.models.anchore_models.AnchoreResponseOk` instance is returned and the result will contain a
            True boolean value if the container image passes the evaluation and a False value if not.
            On a non successful request a :class:`src.models.anchore_models.AnchoreResponseError` instance is returned containing the error message
        :rtype: AnchoreResponse
        """
        try:
            logger.info("Evaluating container image %s against policy %s" % (fulltag, policy_id))
            request_url = self.__host_url + self.__base_path + POLICIES_CHECK.format(image_digest, fulltag, policy_id)
            response = helper.send_get_request_basic_auth(request_url, self.__user, self.__password, self.__verify)
            status_code = response.status_code
            if response.status_code == SUCESS_STATUS_CODE:
                evaluation = False
                if len(response.json()) > 0:
                    evaluation = AnchoreService.__get_policy_evaluation_result(response.json(), image_digest, fulltag)
                return AnchoreResponseOk(status_code=status_code, result=evaluation)
            else:
                error_message = AnchoreService.__get_error_message(response.text)
                return AnchoreResponseError(status_code=status_code, error_message=error_message)
        except Exception as exc:
            logger.exception("Error while trying to get the policies IDs: " + str(exc))
            raise AnchoreServiceException("Error while trying to get the policies IDs: " + str(exc))

    @staticmethod
    def __get_policy_evaluation_result(evaluation_data: List[dict], image_digest: constr(regex=CONTAINER_IMAGE_DIGEST_REGEX),
                                       fulltag: constr(regex=CONTAINER_IMAGE_FULLTAG_REGEX)):
        if len(evaluation_data) > 0:
            status_result = evaluation_data[0][image_digest][fulltag][0]["status"]
            if status_result == "pass":
                return True
        return False

    ############################################
    # CONTENTS
    ############################################
    @validate_arguments
    def get_image_content_types(self, image_digest: constr(regex=CONTAINER_IMAGE_DIGEST_REGEX)) -> AnchoreResponse:
        """Method used to get the available contents of the container image specified by its digest

        :param image_digest: Container image digest value
        :type image_digest: str

        :raises AnchoreServiceException: Exception raised when an unexpected error occurs

        :return: Any subclass instance of :class:`src.models.anchore_models.AnchoreResponse` containing the status code.
            On a successful request a list containing the string of the different content types of the image is returned.
            On a non successful request a :class:`src.models.anchore_models.AnchoreResponseError` instance is returned containing the error message
        :rtype: AnchoreResponse
        """
        try:
            logger.info("Getting container image content types")
            request_url = self.__host_url + self.__base_path + IMAGE_CONTENTS.format(image_digest)
            return self.__get_contents(request_url)
        except Exception as exc:
            logger.exception("Error while trying to get the content types of the image: " + str(exc))
            raise AnchoreServiceException("Error while trying to get the content types of the image: " + str(exc))

    @validate_arguments
    def get_image_contents_by_type(self, image_digest: constr(regex=CONTAINER_IMAGE_DIGEST_REGEX), content_type: str) -> AnchoreResponse:
        """Method used to get the contents of the specified type of the container image specified by its digest

        :param image_digest: Container image digest value
        :type image_digest: str
        :param content_type: The type of content to be retrieved
        :type content_type: str

        :raises AnchoreServiceException: Exception raised when an unexpected error occurs

        :return: Any subclass instance of :class:`src.models.anchore_models.AnchoreResponse` containing the status code.
            On a successful request a JSON containing the contents of the specified type is returned.
            On a non successful request a :class:`src.models.anchore_models.AnchoreResponseError` instance is returned containing the error message
        :rtype: AnchoreResponse
        """
        try:
            logger.info("Getting container image contents by type")
            request_url = self.__host_url + self.__base_path + IMAGE_CONTENTS_BY_TYPE.format(image_digest, content_type)
            return self.__get_contents(request_url)
        except Exception as exc:
            logger.exception("Error while trying to get the contents of the image: " + str(exc))
            raise AnchoreServiceException("Error while trying to get the contents of the image: " + str(exc))

    def __get_contents(self, request_url: AnyHttpUrl):
        response = helper.send_get_request_basic_auth(request_url, self.__user, self.__password, self.__verify)
        status_code = response.status_code
        if response.status_code == SUCESS_STATUS_CODE:
            return AnchoreResponseOk(status_code=status_code, result=response.json())
        else:
            error_message = AnchoreService.__get_error_message(response.text)
            return AnchoreResponseError(status_code=status_code, error_message=error_message)

    def get_image_malware_findings(self, image_digest: constr(regex=CONTAINER_IMAGE_DIGEST_REGEX)) -> AnchoreResponse:
        """Method used to get the information of malware findings in the container image specified by its digest

        :param image_digest: Container image digest value
        :type image_digest: str

        :raises AnchoreServiceException: Exception raised when an unexpected error occurs

        :return: Any subclass instance of :class:`src.models.anchore_models.AnchoreResponse` containing the status code.
            On a successful request a list of dicts is returned with the information of the path and signature of the malware files found.
            Also an empty list willl be returned if no malware is found in the container image.
            On a non successful request a :class:`src.models.anchore_models.AnchoreResponseError` instance is returned containing the error message
        :rtype: AnchoreResponse
        """
        try:
            logger.info("Getting container image malware information")
            malware_info = self.get_image_contents_by_type(image_digest, "malware")
            if isinstance(malware_info, AnchoreResponseOk) and malware_info.status_code == SUCESS_STATUS_CODE:
                malware_info.result = malware_info.result["content"][0]["findings"]
            return malware_info
        except Exception as exc:
            logger.exception("Error while trying to get the container image malware information: " + str(exc))
            raise AnchoreServiceException("Error while trying to get the container image malware information: " + str(exc))
