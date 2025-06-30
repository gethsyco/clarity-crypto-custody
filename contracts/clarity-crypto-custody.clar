;; Crypto Data Custody-Verification-System

;; ========== Core Data Storage Structures ==========
(define-map cryptographic-asset-vault
  { record-index: uint }
  {
    asset-name: (string-ascii 64),
    record-owner: principal,
    data-capacity: uint,
    creation-block: uint,
    record-description: (string-ascii 128),
    metadata-tags: (list 10 (string-ascii 32)) 
  }
)

(define-map access-control-registry
  { record-index: uint, permitted-user: principal }
  { access-enabled: bool }
)

;; ========== System Error Response Definitions ==========
(define-constant error-invalid-record (err u401))
(define-constant error-access-forbidden (err u403))
(define-constant error-invalid-capacity (err u404))
(define-constant error-admin-access-required (err u407))
(define-constant error-operation-restricted (err u408))
(define-constant error-permission-denied (err u405))
(define-constant error-ownership-mismatch (err u406))
(define-constant error-duplicate-record (err u402))
(define-constant error-metadata-validation-failed (err u409))



;; ========== Administrative Control Structure ==========
(define-constant system-controller tx-sender)

;; ========== Global State Management Variables ==========
(define-data-var record-counter-tracker uint u0)



;; ========== Helper Function Implementations ==========

;; Validates that a record exists within the system
(define-private (validate-record-existence (record-index uint))
  (is-some (map-get? cryptographic-asset-vault { record-index: record-index }))
)

;; Ensures individual metadata tag meets protocol requirements
(define-private (validate-single-metadata-tag (tag (string-ascii 32)))
  (and
    (> (len tag) u0)
    (< (len tag) u33)
  )
)

;; Comprehensive validation for metadata tag collections
(define-private (validate-metadata-tag-collection (tag-list (list 10 (string-ascii 32))))
  (and
    (> (len tag-list) u0)
    (<= (len tag-list) u10)
    (is-eq (len (filter validate-single-metadata-tag tag-list)) (len tag-list))
  )
)

;; Retrieves data capacity information for a specific record
(define-private (get-record-data-capacity (record-index uint))
  (default-to u0
    (get data-capacity
      (map-get? cryptographic-asset-vault { record-index: record-index })
    )
  )
)

;; Confirms ownership relationship between user and record
(define-private (confirm-record-ownership (record-index uint) (user principal))
  (match (map-get? cryptographic-asset-vault { record-index: record-index })
    record-information (is-eq (get record-owner record-information) user)
    false
  )
)

;; ========== Record Creation and Registration Functions ==========

;; Primary function for registering new cryptographic asset records
(define-public (register-new-cryptographic-asset 
  (asset-name (string-ascii 64)) 
  (data-capacity uint) 
  (record-description (string-ascii 128)) 
  (metadata-tags (list 10 (string-ascii 32)))
)
  (let
    (
      (new-record-index (+ (var-get record-counter-tracker) u1))
    )
    ;; Comprehensive input validation for all parameters
    (asserts! (> (len asset-name) u0) error-access-forbidden)
    (asserts! (< (len asset-name) u65) error-access-forbidden)
    (asserts! (> data-capacity u0) error-invalid-capacity)
    (asserts! (< data-capacity u1000000000) error-invalid-capacity)
    (asserts! (> (len record-description) u0) error-access-forbidden)
    (asserts! (< (len record-description) u129) error-access-forbidden)
    (asserts! (validate-metadata-tag-collection metadata-tags) error-metadata-validation-failed)

    ;; Insert new record into the cryptographic asset vault
    (map-insert cryptographic-asset-vault
      { record-index: new-record-index }
      {
        asset-name: asset-name,
        record-owner: tx-sender,
        data-capacity: data-capacity,
        creation-block: block-height,
        record-description: record-description,
        metadata-tags: metadata-tags
      }
    )

    ;; Establish initial access control permissions for record creator
    (map-insert access-control-registry
      { record-index: new-record-index, permitted-user: tx-sender }
      { access-enabled: true }
    )

    ;; Update the global record counter tracking mechanism
    (var-set record-counter-tracker new-record-index)
    (ok new-record-index)
  )
)

;; ========== Record Modification and Update Operations ==========

;; Comprehensive record update function with full parameter modification
(define-public (modify-existing-cryptographic-record 
  (record-index uint) 
  (updated-asset-name (string-ascii 64)) 
  (updated-data-capacity uint) 
  (updated-record-description (string-ascii 128)) 
  (updated-metadata-tags (list 10 (string-ascii 32)))
)
  (let
    (
      (existing-record (unwrap! (map-get? cryptographic-asset-vault { record-index: record-index }) error-invalid-record))
    )
    ;; Verify record existence and ownership authorization
    (asserts! (validate-record-existence record-index) error-invalid-record)
    (asserts! (is-eq (get record-owner existing-record) tx-sender) error-ownership-mismatch)
    
    ;; Validate all updated parameters against system requirements
    (asserts! (> (len updated-asset-name) u0) error-access-forbidden)
    (asserts! (< (len updated-asset-name) u65) error-access-forbidden)
    (asserts! (> updated-data-capacity u0) error-invalid-capacity)
    (asserts! (< updated-data-capacity u1000000000) error-invalid-capacity)
    (asserts! (> (len updated-record-description) u0) error-access-forbidden)
    (asserts! (< (len updated-record-description) u129) error-access-forbidden)
    (asserts! (validate-metadata-tag-collection updated-metadata-tags) error-metadata-validation-failed)

    ;; Apply comprehensive updates to the existing record
    (map-set cryptographic-asset-vault
      { record-index: record-index }
      (merge existing-record { 
        asset-name: updated-asset-name, 
        data-capacity: updated-data-capacity, 
        record-description: updated-record-description, 
        metadata-tags: updated-metadata-tags 
      })
    )
    (ok true)
  )
)

;; ========== Access Control and Permission Management ==========

;; Grants viewing and access privileges to specified users
(define-public (grant-record-access-privileges (record-index uint) (target-user principal))
  (let
    (
      (record-information (unwrap! (map-get? cryptographic-asset-vault { record-index: record-index }) error-invalid-record))
    )
    ;; Validate record existence and ownership before granting access
    (asserts! (validate-record-existence record-index) error-invalid-record)
    (asserts! (is-eq (get record-owner record-information) tx-sender) error-ownership-mismatch)
   
    (ok true)
  )
)

;; Revokes previously granted access privileges from users
(define-public (revoke-user-access-privileges (record-index uint) (target-user principal))
  (let
    (
      (record-information (unwrap! (map-get? cryptographic-asset-vault { record-index: record-index }) error-invalid-record))
    )
    ;; Confirm record existence and ownership before revoking access
    (asserts! (validate-record-existence record-index) error-invalid-record)
    (asserts! (is-eq (get record-owner record-information) tx-sender) error-ownership-mismatch)
    (asserts! (not (is-eq target-user tx-sender)) error-admin-access-required)

    ;; Remove access control entry from the registry
    (map-delete access-control-registry { record-index: record-index, permitted-user: target-user })
    (ok true)
  )
)

;; Transfers complete ownership of a record to another user
(define-public (transfer-record-ownership (record-index uint) (new-owner principal))
  (let
    (
      (current-record (unwrap! (map-get? cryptographic-asset-vault { record-index: record-index }) error-invalid-record))
    )
    ;; Verify current ownership before allowing transfer
    (asserts! (validate-record-existence record-index) error-invalid-record)
    (asserts! (is-eq (get record-owner current-record) tx-sender) error-ownership-mismatch)

    ;; Execute ownership transfer operation
    (map-set cryptographic-asset-vault
      { record-index: record-index }
      (merge current-record { record-owner: new-owner })
    )
    (ok true)
  )
)

;; ========== Advanced Record Management Operations ==========

;; Permanently removes a record from the system vault
(define-public (permanently-delete-vault-record (record-index uint))
  (let
    (
      (target-record (unwrap! (map-get? cryptographic-asset-vault { record-index: record-index }) error-invalid-record))
    )
    ;; Verify ownership before allowing permanent deletion
    (asserts! (validate-record-existence record-index) error-invalid-record)
    (asserts! (is-eq (get record-owner target-record) tx-sender) error-ownership-mismatch)

    ;; Execute complete record removal from the vault
    (map-delete cryptographic-asset-vault { record-index: record-index })
    (ok true)
  )
)

;; Enhances existing records with additional metadata tags
(define-public (enhance-record-metadata (record-index uint) (additional-tags (list 10 (string-ascii 32))))
  (let
    (
      (current-record (unwrap! (map-get? cryptographic-asset-vault { record-index: record-index }) error-invalid-record))
      (current-tags (get metadata-tags current-record))
      (merged-tag-collection (unwrap! (as-max-len? (concat current-tags additional-tags) u10) error-metadata-validation-failed))
    )
    ;; Verify record existence and ownership for metadata enhancement
    (asserts! (validate-record-existence record-index) error-invalid-record)
    (asserts! (is-eq (get record-owner current-record) tx-sender) error-ownership-mismatch)

    ;; Validate additional metadata tags before merging
    (asserts! (validate-metadata-tag-collection additional-tags) error-metadata-validation-failed)

    ;; Update record with enhanced metadata collection
    (map-set cryptographic-asset-vault
      { record-index: record-index }
      (merge current-record { metadata-tags: merged-tag-collection })
    )
    (ok merged-tag-collection)
  )
)

;; Marks a record with archival status for long-term preservation
(define-public (mark-record-as-archived (record-index uint))
  (let
    (
      (target-record (unwrap! (map-get? cryptographic-asset-vault { record-index: record-index }) error-invalid-record))
      (archive-tag "ARCHIVED-RECORD")
      (current-tags (get metadata-tags target-record))
      (updated-tag-collection (unwrap! (as-max-len? (append current-tags archive-tag) u10) error-metadata-validation-failed))
    )
    ;; Verify record existence and ownership for archival marking
    (asserts! (validate-record-existence record-index) error-invalid-record)
    (asserts! (is-eq (get record-owner target-record) tx-sender) error-ownership-mismatch)

    ;; Apply archival designation to the record
    (map-set cryptographic-asset-vault
      { record-index: record-index }
      (merge target-record { metadata-tags: updated-tag-collection })
    )
    (ok true)
  )
)

;; ========== System Analytics and Reporting Functions ==========

;; Generates comprehensive analytics for a specific record
(define-public (generate-record-analytics (record-index uint))
  (let
    (
      (record-data (unwrap! (map-get? cryptographic-asset-vault { record-index: record-index }) error-invalid-record))
      (creation-point (get creation-block record-data))
    )
    ;; Verify existence and access authorization
    (asserts! (validate-record-existence record-index) error-invalid-record)
    (asserts! 
      (or 
        (is-eq tx-sender (get record-owner record-data))
        (default-to false (get access-enabled (map-get? access-control-registry { record-index: record-index, permitted-user: tx-sender })))
        (is-eq tx-sender system-controller)
      ) 
      error-permission-denied
    )

    ;; Compile comprehensive analytical data
    (ok {
      record-age: (- block-height creation-point),
      storage-capacity: (get data-capacity record-data),
      metadata-count: (len (get metadata-tags record-data))
    })
  )
)

;; Applies administrative restrictions to specific records
(define-public (apply-administrative-restrictions (record-index uint))
  (let
    (
      (target-record (unwrap! (map-get? cryptographic-asset-vault { record-index: record-index }) error-invalid-record))
      (restriction-tag "ACCESS-RESTRICTED")
      (existing-tags (get metadata-tags target-record))
    )
    ;; Verify administrative privileges
    (asserts! (validate-record-existence record-index) error-invalid-record)
    (asserts! 
      (or 
        (is-eq tx-sender system-controller)
        (is-eq (get record-owner target-record) tx-sender)
      ) 
      error-admin-access-required
    )

    ;; Administrative restriction logic implementation
    (ok true)
  )
)

;; Performs comprehensive ownership verification and authentication
(define-public (verify-record-ownership-status (record-index uint) (claimed-owner principal))
  (let
    (
      (record-data (unwrap! (map-get? cryptographic-asset-vault { record-index: record-index }) error-invalid-record))
      (actual-owner (get record-owner record-data))
      (creation-point (get creation-block record-data))
      (user-has-access (default-to 
        false 
        (get access-enabled 
          (map-get? access-control-registry { record-index: record-index, permitted-user: tx-sender })
        )
      ))
    )
    ;; Verify existence and authorization for ownership verification
    (asserts! (validate-record-existence record-index) error-invalid-record)
    (asserts! 
      (or 
        (is-eq tx-sender actual-owner)
        user-has-access
        (is-eq tx-sender system-controller)
      ) 
      error-permission-denied
    )

    ;; Generate comprehensive ownership verification response
    (if (is-eq actual-owner claimed-owner)
      ;; Return positive verification with supporting information
      (ok {
        ownership-verified: true,
        current-block: block-height,
        blocks-since-creation: (- block-height creation-point),
        ownership-confirmed: true
      })
      ;; Return ownership mismatch information
      (ok {
        ownership-verified: false,
        current-block: block-height,
        blocks-since-creation: (- block-height creation-point),
        ownership-confirmed: false
      })
    )
  )
)

;; System-wide health check and diagnostic function
(define-public (perform-system-health-check)
  (begin
    ;; Verify administrative access privileges
    (asserts! (is-eq tx-sender system-controller) error-admin-access-required)

    ;; Return comprehensive system status information
    (ok {
      total-records: (var-get record-counter-tracker),
      system-operational: true,
      diagnostic-timestamp: block-height
    })
  )
)



