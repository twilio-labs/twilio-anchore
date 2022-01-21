from abc import ABC
from datetime import datetime
from enum import Enum
from typing import Optional, Any, List

from pydantic import BaseModel, StrictStr, constr, AnyHttpUrl, validator

from anchore.contants import CONTAINER_IMAGE_FULLTAG_REGEX, CONTAINER_IMAGE_DIGEST_REGEX, CONTAINER_IMAGE_ID_REGEX


############################################
# EXCEPTIONS
############################################
class AnchoreServiceException(Exception):
    """Anchore exception used when an unexpected error occurs
    """
    pass


############################################
# ENUMS
############################################
class VulnerabilityType(str, Enum):
    """Enum containing the different types of vulnerabilities [os, non-os, all]
    """
    os = "os"
    non_os = "non-os"
    all = "all"


class VulnerabilitySeverity(str, Enum):
    """Enum containing the different vulnerability severities [Critical, High, Medium, Low, Negligible, Unknown]
    """
    critical = "Critical"
    high = "High"
    medium = "Medium"
    low = "Low"
    negligible = "Negligible"
    unknown = "Unknown"


############################################
# REQUESTS RESULTS
############################################
class AnchoreResponse(BaseModel, ABC):
    """Abstract class created to store the responses received from Anchore.

    Subclasses of :class:`src.models.anchore_models.AnchoreResponse` are:
    - :class:`src.models.anchore_models.AnchoreResponseOk`: When the response is successful
    - :class:`src.models.anchore_models.AnchoreResponseError`: When the response contains an error
    """

    status_code: int

    def get_status_code(self) -> int:
        """Returns the status code of the response received from Anchore.

        :return: The status code of the response
        :rtype: int
        """
        return self.status_code


class AnchoreResponseOk(AnchoreResponse):
    """Subclass of :class:`src.models.anchore_models.AnchoreResponse` used to store the results of a successful response received from Anchore.
    :Example:

    .. code-block:: python

        >>> sucessful_response = AnchoreResponseOk(status_code=200, result=[])

    :param status_code: The status code of the response
    :type status_code: int
    :param result: The contents of a successful response
    :type result: Any
    """

    result: Any

    def get_result(self) -> Any:
        """Returns the contents of a succsesful response received from Anchore.

        :return: The contents of a successful response
        :rtype: Any
        """
        return self.result


class AnchoreResponseError(AnchoreResponse):
    """Subclass of :class:`src.models.anchore_models.AnchoreResponse` used to store the results of a failed response received from Anchore.
    :Example:

    .. code-block:: python

        >>> error_response = AnchoreResponseError(status_code=404, error_message="Container Image not found")

    :param status_code: The status code of the response
    :type status_code: int
    :param error_message: The error message
    :type error_message: str
    """
    error_message: StrictStr

    def get_error_message(self) -> str:
        """Returns the error message of the failed response received from Anchore.

        :return: The error message
        :rtype: Any
        """
        return self.error_message


############################################
# ANCHORE MODELS
############################################
class ContainerImage(BaseModel):
    """Class containing the information of a container image

    :param tag: Container image fulltag
    :type tag: str
    :param digest: Container image digest value
    :type digest: str
    :param image_id: Container image id value
    :type image_id: str
    :param analysis_status: The analysis status of the container image [analyzed, not_analyzed, analizing, analysis_failed]
    :type analysis_status: str
    :param image_status: The status of the container image [active, not active]
    :type image_status: str
    :param created_at: The date and time when the container image was submitted to Anchore
    :type created_at: datetime
    :param analyzed_at: The date and time when the container image was analyzed
    :type analyzed_at: datetime, optional
    :param user: The user who submitted the container image to Anchore
    :type user: str
    """
    tag: constr(regex=CONTAINER_IMAGE_FULLTAG_REGEX)
    digest: constr(regex=CONTAINER_IMAGE_DIGEST_REGEX)
    image_id: constr(regex=CONTAINER_IMAGE_ID_REGEX)
    analysis_status: StrictStr
    image_status: StrictStr
    created_at: datetime
    analyzed_at: Optional[datetime] = None
    user: StrictStr

    def __init__(self, **kwargs):
        kwargs["tag"] = kwargs["image_detail"][0]["fulltag"]
        kwargs["digest"] = kwargs["image_detail"][0]["imageDigest"]
        kwargs["image_id"] = kwargs["image_detail"][0]["imageId"]
        kwargs["user"] = kwargs["userId"]
        super().__init__(**kwargs)


class Vulnerability(BaseModel):
    """Class containing the information of a vulnerability found in a container image

    :param vuln: The unique identifier of the vulnerability
    :type vuln: str
    :param severity: Container image digest value
    :type severity: str
    :param feed_group: Feed group containing the information of the vulnerability
    :type feed_group: str
    :param package: The package where the vulnerability was found
    :type package: str
    :param package_type: The type of the package where the vulnerability was found
    :type package_type: str
    :param package_path: The path to the package where the vulnerability was found
    :type package_path: str
    :param package_version: The version of the package where the vulnerability was found
    :type package_version: str
    :param url: URL pointing to the public information of the vulnerability
    :type url: AnyHttpUrl
    :param inherited_from_base: If true it indicates that the vulnerability was inherited from the base container image
    :type inherited_from_base: bool
    """
    vuln: StrictStr
    severity: VulnerabilitySeverity
    feed_group: StrictStr
    package: StrictStr
    package_type: StrictStr
    package_path: StrictStr
    package_version: StrictStr
    fix: Optional[StrictStr] = None
    url: AnyHttpUrl
    inherited_from_base: Optional[bool] = None

    @validator('fix')
    def check_none_fix(cls, v):
        if v == "None":
            return None
        return v


class InventoryImage(BaseModel):
    """Class containing the information of a single entry of the runtime inventory

    :param context_list vuln: Each context in the list has the information of the K8s cluster and the namespace
    :type context_list: List of str
    :param tag: Container image fulltag
    :type tag: str
    :param digest: Container image digest value
    :type digest: str
    :param created_at: The date and time when the container image was submitted to the Anchore inventory
    :type created_at: datetime
    :param last_seen: The date and time when the container image was last seen in the context
    :type last_seen: datetime
    :param last_updated: The date and time when the container image was updated for the last time
    :type last_updated: datetime
    """
    context_list: List[StrictStr]
    tag: constr(regex=CONTAINER_IMAGE_FULLTAG_REGEX)
    digest: StrictStr
    created_at: datetime
    last_seen: datetime
    last_updated: datetime

    def __init__(self, **kwargs):
        kwargs["context_list"] = [kwargs["context"]]
        kwargs["tag"] = kwargs["image_tag"]
        kwargs["digest"] = kwargs["image_digest"]
        super().__init__(**kwargs)

    @staticmethod
    def get_cluster_from_context(context: str) -> str:
        """Returns the name of the cluster of the given context

        :param context: The context containing the cluster and the namespace where the container image was found
        :type context: str
        :return: The name of the cluster
        :rtype: str
        """
        slash_delimiter = context.find("/")
        cluster = context[:slash_delimiter]
        return cluster

    @staticmethod
    def get_namespace_from_context(context: str) -> str:
        """Returns the namespace from the given context

        :param context: The context containing the cluster and the namespace where the container image was found
        :type context: str
        :return: The namespace
        :rtype: str
        """
        slash_delimiter = context.find("/")
        namespace = context[slash_delimiter + 1:]
        return namespace

    def get_list_of_clusters(self) -> List[str]:
        """Returns the list of the inventory clusters where the image was found

        :return: A list containing the name of the clusters where the image was found
        :rtype: List of str
        """
        result = []
        for context in self.context_list:
            result.append(self.get_cluster_from_context(context))
        return list(set(result))
