"""HTTP Status Codes compatible with requests.codes."""

class _Codes:
    ok = OK = 200
    created = CREATED = 201
    accepted = ACCEPTED = 202
    non_authoritative_information = 203
    no_content = NO_CONTENT = 204
    reset_content = 205
    partial_content = 206
    multi_status = 207
    already_reported = 208
    im_used = 226

    # Redirection
    multiple_choices = 300
    moved_permanently = MOVED_PERMANENTLY = 301
    found = FOUND = 302
    see_other = SEE_OTHER = 303
    not_modified = NOT_MODIFIED = 304
    use_proxy = 305
    temporary_redirect = TEMPORARY_REDIRECT = 307
    permanent_redirect = PERMANENT_REDIRECT = 308

    # Client Errors
    bad_request = BAD_REQUEST = 400
    unauthorized = UNAUTHORIZED = 401
    payment_required = 402
    forbidden = FORBIDDEN = 403
    not_found = NOT_FOUND = 404
    method_not_allowed = METHOD_NOT_ALLOWED = 405
    not_acceptable = 406
    proxy_authentication_required = 407
    request_timeout = REQUEST_TIMEOUT = 408
    conflict = CONFLICT = 409
    gone = GONE = 410
    length_required = 411
    precondition_failed = 412
    payload_too_large = 413
    uri_too_long = 414
    unsupported_media_type = 415
    range_not_satisfiable = 416
    expectation_failed = 417
    im_a_teapot = 418
    misdirected_request = 421
    unprocessable_entity = UNPROCESSABLE_ENTITY = 422
    locked = 423
    failed_dependency = 424
    too_early = 425
    upgrade_required = 426
    precondition_required = 428
    too_many_requests = TOO_MANY_REQUESTS = 429
    request_header_fields_too_large = 431
    unavailable_for_legal_reasons = 451

    # Server Errors
    internal_server_error = INTERNAL_SERVER_ERROR = 500
    not_implemented = NOT_IMPLEMENTED = 501
    bad_gateway = BAD_GATEWAY = 502
    service_unavailable = SERVICE_UNAVAILABLE = 503
    gateway_timeout = GATEWAY_TIMEOUT = 504
    http_version_not_supported = 505
    variant_also_negotiates = 506
    insufficient_storage = 507
    loop_detected = 508
    not_extended = 510
    network_authentication_required = 511

    def __getitem__(self, key):
        return getattr(self, str(key).lower())

codes = _Codes()
