# AnchoreService class
Main anchore-python library class used to execute the different Anchore API endpoints.   
The following methods use Anchore Enterprise features, don't use them if Anchore Enterprise is not available:
*   **get_vulnerabilities_by_digest** (if the parameter _baseimage_digest_ is not None)
*   **get_base_image_digest**
*   **get_inventory**

Example:
```python
anchore_service = AnchoreService("https://analyzer.anchore.com", "anchoreuser", "password")
```
##### Init method
```python
class src.anchore.service.AnchoreService(host_url: AnyHttpUrl, user: str, password: str, base_path: str = '/v1', enterprise_base_path: str = '/v1/enterprise', verify: bool = True)
```
##### Parameters

*   **host_url** (_AnyHttpUrl_) – Anchore Engine URL
*   **user** (_str_) – Required user to connect to Anchore
*   **password** (_str_) – Password of the user
*   **base_path** (_str_, _optional_) – Initial URL segment of the Anchore API
*   **enterprise_base_path** (_str_, _optional_) – Initial URL segment of the Enterprise Anchore API
*   **verify** (_bool_, _optional_) – Boolean value used to verify Anchore certificate

## AnchoreService Methods

### add_image
Submits a new image to be analyzed by Anchore.
```python
add_image(fulltag: str, force: bool = False) → src.anchore.models.AnchoreResponse
```
##### Parameters
*   **fulltag** (_str_) – Container image fulltag
*   **force** (_bool_, _optional_) – If true, the image will be added to the queue even if the image has been analyzed before

##### Raises
_AnchoreServiceException_ - Exception raised when an unexpected error occurs

##### Returns
Any subclass instance of _src.anchore.models.AnchoreResponse_ containing the status code.   
On a successful request a _src.anchore.models.AnchoreResponseOk_ instance is returned and the result will contain a True boolean value if the container image passes the evaluation and a False value if not.   
On a non successful request a _src.anchore.models.AnchoreResponseError_ instance is returned containing the error message.

### get_image
Method used to get the information of a container image specified by its fulltag
```python
get_image(fulltag: str) → src.anchore.models.AnchoreResponse
```
##### Parameters
*   **fulltag** (_str_) – Container image fulltag

##### Raises
_AnchoreServiceException_ - Exception raised when an unexpected error occurs

##### Returns
Any subclass instance of _src.anchore.models.AnchoreResponse_ containing the status code.   
On a successful request a _src.anchore.models.AnchoreResponseOk_ instance is returned and the result will contain a _src.anchore.models.ContainerImage_ instance.   
On a non successful request a _src.anchore.models.AnchoreResponseError_ instance is returned containing the error message.


### get_image_by_digest
Method used to get the information of a container image specified by its digest value
```python
get_image_by_digest(image_digest: str) → src.anchore.models.AnchoreResponse
```
##### Parameters
*   **image_digest** (_str_) – Container image digest value

##### Raises
_AnchoreServiceException_ - Exception raised when an unexpected error occurs

##### Returns
Any subclass instance of _src.anchore.models.AnchoreResponse_ containing the status code.   
On a successful request a _src.anchore.models.AnchoreResponseOk_ instance is returned and the result will contain a _src.anchore.models.ContainerImage_ instance.   
On a non successful request a _src.anchore.models.AnchoreResponseError_ instance is returned containing the error message.


### get_vulnerabilities_by_digest
Method used to get the vulnerabilities of the image specified by its digest.
```python
get_vulnerabilities_by_digest(image_digest: str, vtype: src.anchore.models.VulnerabilityType = VulnerabilityType.all, severity_list: List[src.anchore.models.VulnerabilitySeverity] = None, fix_required: bool = False, baseimage_digest: str = None) → src.anchore.models.AnchoreResponse
```
##### Parameters
*   **image_digest** (_str_) – Container image digest value
*   **vtype** (_src.anchore.models.VulnerabilityType_, _optional_) – The type of vulnerabilities to be returned [os, non-os, all]
*   **severity_list** (_List of VulnerabilitySeverity_, _optional_) – Severities of the vulnerabilities to be returned
*   **fix_required** (_bool_, _optional_) – If True only vulnerabilities with a known fix will be returned
*   **baseimage_digest** (_str_, _optional_) – Base image digest value. This is an Enterprise feature. If not None, information about whether the vulnerability is inherited from the base image or not is added

##### Raises
_AnchoreServiceException_ - Exception raised when an unexpected error occurs

##### Returns
Any subclass instance of _src.anchore.models.AnchoreResponse_ containing the status code.   
On a successful request a _src.anchore.models.AnchoreResponseOk_ instance is returned and the result will contain a list of _src.anchore.models.Vulnerability_ instances.   
The list can be empty if the container image does not have any vulnerability.   
On a non successful request a _src.anchore.models.AnchoreResponseError_ instance is returned containing the error message.

### get_vulnerabilities_by_id
Method used to get the vulnerabilities of the image specified by its id.
```python
get_vulnerabilities_by_id(_image_id: str, vtype: src.anchore.models.VulnerabilityType = VulnerabilityType.all, severity_list: List[src.anchore.models.VulnerabilitySeverity] = None, fix_required: bool = False) →  src.anchore.models.AnchoreResponse
```
##### Parameters
*   **image_id** (_str_) – Container image id value
*   **vtype** (_src.anchore.models.VulnerabilityType_, _optional_) – The type of vulnerabilities to be returned [os, non-os, all]
*   **severity_list** (_List of VulnerabilitySeverity_, _optional_) – Severities of the vulnerabilities to be returned
*   **fix_required** (_bool_, _optional_) – If True only vulnerabilities with a known fix will be returned

##### Raises
_AnchoreServiceException_ - Exception raised when an unexpected error occurs

##### Returns
Any subclass instance of _src.anchore.models.AnchoreResponse_ containing the status code.   
On a successful request a _src.anchore.models.AnchoreResponseOk_ instance is returned and the result will contain a list of _src.anchore.models.Vulnerability_ instances.   
The list can be empty if the container image does not have any vulnerability.   
On a non successful request a _src.anchore.models.AnchoreResponseError_ instance is returned containing the error message.


### get_policies_ids
Method used to get a list containing all the existing policies IDs
```python
get_policies_ids() → src.anchore.models.AnchoreResponse
```
##### Raises
_AnchoreServiceException_ - Exception raised when an unexpected error occurs

##### Returns
Any subclass instance of _src.anchore.models.AnchoreResponse_ containing the status code.   
On a successful request a _src.anchore.models.AnchoreResponseOk_ instance is returned and the result will contain the list of the different policies IDs.   
On a non successful request a _src.anchore.models.AnchoreResponseError_ instance is returned containing the error message.


### evaluate_policy
Method used to check if the specified image passes the evaluation against the specified policy
```python
evaluate_policy(image_digest: str, fulltag: str, policy_id: str) → src.anchore.models.AnchoreResponse
```
##### Parameters
*   **image_digest** (_str_) – Container image digest value
*   **fulltag** (_str_) – Container image fulltag
*   **policy_id** (_str_) – Id of the policy

##### Raises
_AnchoreServiceException_ - Exception raised when an unexpected error occurs

##### Returns
Any subclass instance of _src.anchore.models.AnchoreResponse_ containing the status code.   
On a successful request a _src.anchore.models.AnchoreResponseOk_ instance is returned and the result will contain a True boolean value if the container image passes the evaluation and a False value if not.   
On a non successful request a _src.anchore.models.AnchoreResponseError_ instance is returned containing the error message.


### get_baseimage_digest
Method used to check if the specified image passes the evaluation against the specified policy
```python
get_baseimage_digest(image_digest: str) → src.anchore.models.AnchoreResponse
```
##### Parameters
*   **image_digest** (_str_) – Container image digest value

##### Raises
_AnchoreServiceException_ - Exception raised when an unexpected error occurs

##### Returns
Any subclass instance of _src.anchore.models.AnchoreResponse_ containing the status code.   
On a successful request a _src.anchore.models.AnchoreResponseOk_ instance is returned and the result will contain the base image digest, or None if the specified container image does not have a known base image.   
On a non successful request a _src.anchore.models.AnchoreResponseError_ instance is returned containing the error message.


### get_image_content_types
Method used to get the available contents of the container image specified by its digest
```python
get_image_content_types(image_digest: str) → src.anchore.models.AnchoreResponse
```
##### Parameters
*   **image_digest** (_str_) – Container image digest value

##### Raises
_AnchoreServiceException_ - Exception raised when an unexpected error occurs

##### Returns
Any subclass instance of _src.anchore.models.AnchoreResponse_ containing the status code.   
On a successful request a JSON containing the contents of the specified type is returned.   
On a non successful request a _src.anchore.models.AnchoreResponseError_ instance is returned containing the error message.


### get_image_contents_by_type
Method used to get the contents of the specified type of the container image specified by its digest
```python
get_image_contents_by_type(image_digest: str, content_type: str) → src.anchore.models.AnchoreResponse
```
##### Parameters
*   **image_digest** (_str_) – Container image digest value
*   **content_type** (_str_) – The type of content to be retrieved

##### Raises
_AnchoreServiceException_ - Exception raised when an unexpected error occurs

##### Returns
Any subclass instance of _src.anchore.models.AnchoreResponse_ containing the status code.   
On a successful request a JSON containing the contents of the specified type is returned.   
On a non successful request a _src.anchore.models.AnchoreResponseError_ instance is returned containing the error message.


### get_image_malware_findings
Method used to get the information of malware findings in the container image specified by its digest
```python
get_image_malware_findings(image_digest: str) → src.anchore.models.AnchoreResponse
```
##### Parameters
*   **image_digest** (_str_) – Container image digest value

##### Raises
_AnchoreServiceException_ - Exception raised when an unexpected error occurs

##### Returns
Any subclass instance of _src.anchore.models.AnchoreResponse_ containing the status code.   
On a successful request a list of dicts is returned with the information of the path and signature of the malware files found.   
An empty list will be returned if no malware is found in the container image.   
On a non successful request a _src.anchore.models.AnchoreResponseError_ instance is returned containing the error message.


### get_inventory
Method used to get a list containing the container images of the inventory
```python
get_inventory(group_by_image: bool = False) → src.anchore.models.AnchoreResponse
```
##### Parameters
*   **group_by_image** (_bool_, _optional_) – If true, the container images with the same digest are grouped and the information of the different contexts are added to the list of contexts. If false, each inventory entry is added to the inventory list.

##### Raises
_AnchoreServiceException_ - Exception raised when an unexpected error occurs

##### Returns
Any subclass instance of _src.anchore.models.AnchoreResponse_ containing the status code.   
On a successful request a _src.anchore.models.AnchoreResponseOk_ instance is returned and the result will contain a list of _src.anchore.models.InventoryImage_ instances.   
On a non successful request a _src.anchore.models.AnchoreResponseError_ instance is returned containing the error message.
