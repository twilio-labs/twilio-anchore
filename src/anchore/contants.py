############################################
# STATUS CODES
############################################
SUCESS_STATUS_CODE = 200
NOT_FOUND_STATUS_CODE = 404
UNAUTHORIZED_STATUS_CODE = 401
ERROR_STATUS_CODE = 500

############################################
# REGEX
############################################
CONTAINER_IMAGE_FULLTAG_REGEX = "^[a-zA-Z0-9.:/\-_]{1,250}$"
CONTAINER_IMAGE_DIGEST_REGEX = "^sha256:[a-zA-Z0-9]{64}$"
CONTAINER_IMAGE_ID_REGEX = "^[a-zA-Z0-9]{64}$"

###############################
# BASE PATHS & ENDPOINTS
###############################
BASE_PATH = "/v1"
ENTERPRISE_BASE_PATH = "/v1/enterprise"

IMAGES_REQUEST = "/images?fulltag={}"
IMAGES_REQUEST_DIGEST = "/images/{}"
ADD_IMAGE_REQUEST = "/images?force={}"
VULN_REQUEST_ID = "/images/by_id/{}/vuln/{}"
VULN_REQUEST_DIGEST = "/images/{}/vuln/{}"

ENTERPRISE_INVENTORY = "/inventories"
ENTERPRISE_ANCESTORS = "/images/{}/ancestors"
ENTERPRISE_VULN_REQUEST_DIGEST_PARENT = "/images/{}/vuln/{}?base_digest={}"

POLICIES_IDS_REQUEST = "/policies"
POLICIES_CHECK = "/images/{}/check?tag={}&policyId={}&detail=false"

IMAGE_CONTENTS = "/images/{}/content"
IMAGE_CONTENTS_BY_TYPE = "/images/{}/content/{}"
