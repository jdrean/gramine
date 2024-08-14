/* SPDX-License-Identifier: LGPL-3.0-or-later */

#pragma once

#include "tyche_capabilities_types.h"
void handle_ecall(capa_index_t ret_index, void* ecall_args, void* enclave_base_addr);
