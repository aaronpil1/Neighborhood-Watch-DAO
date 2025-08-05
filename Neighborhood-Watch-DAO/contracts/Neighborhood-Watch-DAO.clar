;; Neighborhood Watch DAO - Community Security & Safety Reporting System
;; A decentralized autonomous organization for community-governed security monitoring

;; Constants
(define-constant CONTRACT-OWNER tx-sender)
(define-constant ERR-OWNER-ONLY (err u100))
(define-constant ERR-NOT-MEMBER (err u101))
(define-constant ERR-ALREADY-MEMBER (err u102))
(define-constant ERR-INSUFFICIENT-STAKE (err u103))
(define-constant ERR-REPORT-NOT-FOUND (err u104))
(define-constant ERR-ALREADY-VOTED (err u105))
(define-constant ERR-INVALID-SEVERITY (err u106))
(define-constant ERR-PROPOSAL-NOT-FOUND (err u107))
(define-constant ERR-VOTING-ENDED (err u108))
(define-constant ERR-INSUFFICIENT-REPUTATION (err u109))

;; Minimum stake required to join DAO (in microSTX)
(define-constant MIN-STAKE u1000000) ;; 1 STX
(define-constant MIN-REPUTATION u10)
(define-constant VOTING-PERIOD u1440) ;; blocks (~10 days)

;; Data Variables
(define-data-var report-counter uint u0)
(define-data-var proposal-counter uint u0)
(define-data-var total-members uint u0)

;; Member structure
(define-map members
  principal
  {
    stake: uint,
    reputation: uint,
    reports-submitted: uint,
    votes-cast: uint,
    join-height: uint,
    active: bool
  }
)

;; Security reports structure
(define-map security-reports
  uint
  {
    reporter: principal,
    location-hash: (buff 32), ;; Hashed location for privacy
    severity: uint, ;; 1-5 scale
    category: (string-ascii 20),
    description-hash: (buff 32),
    timestamp: uint,
    verified: bool,
    votes-for: uint,
    votes-against: uint,
    total-votes: uint,
    resolved: bool,
    resolution-height: (optional uint)
  }
)

;; DAO governance proposals
(define-map governance-proposals
  uint
  {
    proposer: principal,
    title: (string-ascii 50),
    description-hash: (buff 32),
    proposal-type: uint, ;; 1=parameter change, 2=member removal, 3=fund allocation
    target: (optional principal),
    value: (optional uint),
    votes-for: uint,
    votes-against: uint,
    start-height: uint,
    end-height: uint,
    executed: bool,
    quorum-met: bool
  }
)

;; Vote tracking
(define-map report-votes
  { report-id: uint, voter: principal }
  { vote: bool, weight: uint }
)

(define-map proposal-votes
  { proposal-id: uint, voter: principal }
  { vote: bool, weight: uint }
)

;; Member reputation history
(define-map reputation-log
  { member: principal, action-id: uint }
  { action-type: (string-ascii 20), points: int, height: uint }
)

;; Read-only functions

(define-read-only (get-member-info (member principal))
  (map-get? members member)
)

(define-read-only (get-security-report (report-id uint))
  (map-get? security-reports report-id)
)

(define-read-only (get-governance-proposal (proposal-id uint))
  (map-get? governance-proposals proposal-id)
)

(define-read-only (get-total-members)
  (var-get total-members)
)

(define-read-only (get-report-count)
  (var-get report-counter)
)

(define-read-only (is-member (address principal))
  (match (map-get? members address)
    member (get active member)
    false
  )
)

(define-read-only (calculate-voting-weight (member principal))
  (match (map-get? members member)
    member-data (+ (get stake member-data) (* (get reputation member-data) u100))
    u0
  )
)

;; Public functions

;; Join the DAO
(define-public (join-dao)
  (let
    (
      (stake-amount (stx-get-balance tx-sender))
    )
    (asserts! (>= stake-amount MIN-STAKE) ERR-INSUFFICIENT-STAKE)
    (asserts! (is-none (map-get? members tx-sender)) ERR-ALREADY-MEMBER)
    
    (try! (stx-transfer? MIN-STAKE tx-sender (as-contract tx-sender)))
    
    (map-set members tx-sender
      {
        stake: MIN-STAKE,
        reputation: u50, ;; Starting reputation
        reports-submitted: u0,
        votes-cast: u0,
        join-height: block-height,
        active: true
      }
    )
    
    (var-set total-members (+ (var-get total-members) u1))
    (ok true)
  )
)

;; Submit security report
(define-public (submit-security-report 
    (location-hash (buff 32))
    (severity uint)
    (category (string-ascii 20))
    (description-hash (buff 32))
  )
  (let
    (
      (report-id (+ (var-get report-counter) u1))
      (reporter-data (unwrap! (map-get? members tx-sender) ERR-NOT-MEMBER))
    )
    (asserts! (get active reporter-data) ERR-NOT-MEMBER)
    (asserts! (and (>= severity u1) (<= severity u5)) ERR-INVALID-SEVERITY)
    
    (map-set security-reports report-id
      {
        reporter: tx-sender,
        location-hash: location-hash,
        severity: severity,
        category: category,
        description-hash: description-hash,
        timestamp: block-height,
        verified: false,
        votes-for: u0,
        votes-against: u0,
        total-votes: u0,
        resolved: false,
        resolution-height: none
      }
    )
    
    ;; Update reporter stats
    (map-set members tx-sender
      (merge reporter-data 
        { reports-submitted: (+ (get reports-submitted reporter-data) u1) }
      )
    )
    
    (var-set report-counter report-id)
    (ok report-id)
  )
)

;; Vote on security report verification
(define-public (vote-on-report (report-id uint) (vote-for bool))
  (let
    (
      (report-data (unwrap! (map-get? security-reports report-id) ERR-REPORT-NOT-FOUND))
      (voter-data (unwrap! (map-get? members tx-sender) ERR-NOT-MEMBER))
      (vote-key { report-id: report-id, voter: tx-sender })
      (voting-weight (calculate-voting-weight tx-sender))
    )
    (asserts! (get active voter-data) ERR-NOT-MEMBER)
    (asserts! (>= (get reputation voter-data) MIN-REPUTATION) ERR-INSUFFICIENT-REPUTATION)
    (asserts! (is-none (map-get? report-votes vote-key)) ERR-ALREADY-VOTED)
    (asserts! (not (get resolved report-data)) ERR-VOTING-ENDED)
    
    ;; Record vote
    (map-set report-votes vote-key
      { vote: vote-for, weight: voting-weight }
    )
    
    ;; Update report vote counts
    (map-set security-reports report-id
      (merge report-data
        {
          votes-for: (if vote-for 
            (+ (get votes-for report-data) voting-weight)
            (get votes-for report-data)
          ),
          votes-against: (if vote-for
            (get votes-against report-data)
            (+ (get votes-against report-data) voting-weight)
          ),
          total-votes: (+ (get total-votes report-data) voting-weight),
          verified: (> (+ (get votes-for report-data) 
                       (if vote-for voting-weight u0))
                       (+ (get votes-against report-data)
                       (if vote-for u0 voting-weight)))
        }
      )
    )
    
    ;; Update voter stats
    (map-set members tx-sender
      (merge voter-data 
        { votes-cast: (+ (get votes-cast voter-data) u1) }
      )
    )
    
    (ok true)
  )
)

;; Create governance proposal
(define-public (create-proposal 
    (title (string-ascii 50))
    (description-hash (buff 32))
    (proposal-type uint)
    (target (optional principal))
    (value (optional uint))
  )
  (let
    (
      (proposal-id (+ (var-get proposal-counter) u1))
      (proposer-data (unwrap! (map-get? members tx-sender) ERR-NOT-MEMBER))
    )
    (asserts! (get active proposer-data) ERR-NOT-MEMBER)
    (asserts! (>= (get reputation proposer-data) u100) ERR-INSUFFICIENT-REPUTATION)
    
    (map-set governance-proposals proposal-id
      {
        proposer: tx-sender,
        title: title,
        description-hash: description-hash,
        proposal-type: proposal-type,
        target: target,
        value: value,
        votes-for: u0,
        votes-against: u0,
        start-height: block-height,
        end-height: (+ block-height VOTING-PERIOD),
        executed: false,
        quorum-met: false
      }
    )
    
    (var-set proposal-counter proposal-id)
    (ok proposal-id)
  )
)

;; Vote on governance proposal
(define-public (vote-on-proposal (proposal-id uint) (vote-for bool))
  (let
    (
      (proposal-data (unwrap! (map-get? governance-proposals proposal-id) ERR-PROPOSAL-NOT-FOUND))
      (voter-data (unwrap! (map-get? members tx-sender) ERR-NOT-MEMBER))
      (vote-key { proposal-id: proposal-id, voter: tx-sender })
      (voting-weight (calculate-voting-weight tx-sender))
    )
    (asserts! (get active voter-data) ERR-NOT-MEMBER)
    (asserts! (<= block-height (get end-height proposal-data)) ERR-VOTING-ENDED)
    (asserts! (is-none (map-get? proposal-votes vote-key)) ERR-ALREADY-VOTED)
    
    ;; Record vote
    (map-set proposal-votes vote-key
      { vote: vote-for, weight: voting-weight }
    )
    
    ;; Update proposal vote counts
    (map-set governance-proposals proposal-id
      (merge proposal-data
        {
          votes-for: (if vote-for 
            (+ (get votes-for proposal-data) voting-weight)
            (get votes-for proposal-data)
          ),
          votes-against: (if vote-for
            (get votes-against proposal-data)
            (+ (get votes-against proposal-data) voting-weight)
          ),
          quorum-met: (>= (+ (get votes-for proposal-data) 
                            (get votes-against proposal-data) 
                            voting-weight)
                         (/ (* (var-get total-members) u3) u10)) ;; 30% quorum
        }
      )
    )
    
    (ok true)
  )
)

;; Update member reputation (only contract can call)
(define-private (update-reputation (member principal) (points int) (action-type (string-ascii 20)))
  (match (map-get? members member)
    member-data
      (let
        (
          (current-rep (get reputation member-data))
          (new-rep (if (> points 0)
                     (+ current-rep (to-uint points))
                     (if (> current-rep (to-uint (- points)))
                       (- current-rep (to-uint (- points)))
                       u0)))
        )
        (map-set members member
          (merge member-data { reputation: new-rep })
        )
        (ok new-rep)
      )
    ERR-NOT-MEMBER
  )
)

;; Resolve security report (admin function)
(define-public (resolve-report (report-id uint))
  (let
    (
      (report-data (unwrap! (map-get? security-reports report-id) ERR-REPORT-NOT-FOUND))
    )
    (asserts! (or (is-eq tx-sender CONTRACT-OWNER) 
                  (is-eq tx-sender (get reporter report-data))) ERR-OWNER-ONLY)
    
    (map-set security-reports report-id
      (merge report-data
        {
          resolved: true,
          resolution-height: (some block-height)
        }
      )
    )
    
    ;; Award reputation to reporter if verified
    (if (get verified report-data)
      (try! (update-reputation (get reporter report-data) 10 "report-verified"))
      (try! (update-reputation (get reporter report-data) -5 "report-rejected"))
    )
    
    (ok true)
  )
)

;; Emergency pause (owner only)
(define-public (emergency-pause)
  (begin
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-OWNER-ONLY)
    ;; Additional emergency logic would go here
    (ok true)
  )
)