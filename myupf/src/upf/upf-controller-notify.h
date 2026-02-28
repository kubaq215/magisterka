/*
 * Copyright (C) 2026
 *
 * This file is part of Open5GS.
 */

#ifndef UPF_CONTROLLER_NOTIFY_H
#define UPF_CONTROLLER_NOTIFY_H

#include "context.h"

int upf_controller_notify_session_establish(upf_sess_t *sess);
int upf_controller_notify_session_modify(upf_sess_t *sess,
        ogs_pfcp_pdr_t **modified_pdr, int num_modified_pdr,
        ogs_pfcp_far_t **modified_far, int num_modified_far);
int upf_controller_notify_session_delete(upf_sess_t *sess);

#endif /* UPF_CONTROLLER_NOTIFY_H */
