# Classes Documentation

## ContainerImage
Class containing the information of a container image.

### Init
```python
class src.anchore.models.ContainerImage(tag: str, digest: str, image_id: str, analysis_status: str, image_status: str, created_at: datetime.datetime, analyzed_at: datetime.datetime = None, user: str)
```
##### Parameters
*   **tag** (_str_) – Container image fulltag
*   **digest** (_str_) – Container image digest value
*   **image_id** (_str_) – Container image id value
*   **analysis_status** (_str_) – The analysis status of the container image [analyzed, not_analyzed, analizing, analysis_failed]
*   **image_status** (_str_) – The status of the container image [active, not active]
*   **created_at** (_datetime_) – The date and time when the container image was submitted to Anchore
*   **analyzed_at** (_datetime_, _optional_) – The date and time when the container image was analyzed
*   **user** (_str_) – The user who submitted the container image to Anchore


## Vulnerability
Class containing the information of a vulnerability found in a container image.

### Init
```python
class src.anchore.models.Vulnerability(vuln: str, severity: src.anchore.models.VulnerabilitySeverity, feed_group: str, package: str, package_type: str, package_path: str, package_version: str, fix: str = None, url: pydantic.networks.AnyHttpUrl, inherited_from_base: bool = None)
```
##### Parameters
*   **vuln** (_str_) – The unique identifier of the vulnerability
*   **severity** (_str_) – Container image digest value
*   **feed_group** (_str_) – Feed group containing the information of the vulnerability
*   **package** (_str_) – The package where the vulnerability was found
*   **package_type** (_str_) – The type of the package where the vulnerability was found
*   **package_path** (_str_) – The path to the package where the vulnerability was found
*   **package_version** (_str_) – The version of the package where the vulnerability was found
*   **url** (_AnyHttpUrl_) – URL pointing to the public information of the vulnerability
*   **inherited_from_base** (_bool_) – If true it indicates that the vulnerability was inherited from the base container image


## InventoryImage
Class containing the information of a single entry of the runtime inventory

### Init
```python
class src.anchore.models.InventoryImage(context_list: List[str], tag: str, digest: str, created_at: datetime.datetime, last_seen: datetime.datetime, last_updated: datetime.datetime)
```
##### Parameters
*   **context_list** (_List[str]_) – Each context in the list has the information of the K8s cluster and the namespace
*   **tag** (_str_) – Container image fulltag
*   **digest** (_str_) – Container image digest value
*   **created_at** (_datetime_) – The date and time when the container image was submitted to the Anchore inventory
*   **last_seen** (_datetime_) – The date and time when the container image was last seen in the context
*   **last_updated** (_datetime_) – The date and time when the container image was updated for the last time
### get_cluster_from_context
Returns the name of the cluster of the given context.
```python
static get_cluster_from_context(context: str) → str
```
##### Parameters
*   **context** (_str_) – The context containing the cluster and the namespace where the container image was found
##### Returns
Returns the name of the cluster of the given context
### get_namespace_from_context
Returns the namespace from the given context.
```python
static get_namespace_from_context(context: str) → str
```
##### Parameters
*   **context** (_str_) – The context containing the cluster and the namespace where the container image was found
##### Returns
Returns the namespace from the given context.
### get_list_of_clusters
Returns the list of the inventory clusters where the image was found.
```python
static get_list_of_clusters() → List[str]
```
##### Returns
Returns the list of the inventory clusters where the image was found


## AnchoreResponse
Abstract class created to store the responses received from Anchore.   
Subclasses of _src.anchore.models.AnchoreResponse_ are:
- **_src.anchore.models.AnchoreResponseOk_**: When the response is successful
- **_src.anchore.models.AnchoreResponseError_**: When the response contains an error

### get_status_code
Returns the status code of the response received from Anchore.
```python
get_status_code() → int
```
##### Returns
The status code of the response


## AnchoreResponseOk
Subclass of _src.anchore.models.AnchoreResponse_ used to store the results of a successful response received from Anchore.

### Init
```python
class src.anchore.models.AnchoreResponseOk(status_code: int, result: str)
```
##### Parameters
*   **status_code** (_int_) – The status code of the response
*   **result** (_Any_) – The contents of a successful response
Example:    
```python
sucessful_response = AnchoreResponseOk(status_code=200, result=[])
```
#### get_result
Returns the contents of a successful response received from Anchore.
```python
get_result() → Any
```
##### Returns
The contents of a successful response


## AnchoreResponseError
Subclass of _src.anchore.models.AnchoreResponse_ used to store the results of a failed response received from Anchore.
### Init
```python
class src.anchore.models.AnchoreResponseError(status_code: int, error_message: str)
```
##### Parameters
*   **status_code** (_int_) – The status code of the response
*   **error_message** (_str_) – The error message
Example:    
```python
error_response = AnchoreResponseError(status_code=404, error_message="Container Image not found")
```
#### get_error_message
Returns the error message of the failed response received from Anchore.
```python
get_error_message() → str
```
##### Returns
The error message


## AnchoreServiceException
Anchore exception class used when an unexpected error occurs.
