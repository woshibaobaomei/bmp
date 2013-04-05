#include <cdefs.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
 

/*
 * Min. ASPATH attribute for eBGP routes.
 */
#define EBGP_ASPATH_MIN (ASPATH_SEGMENT_OVERHEAD + ASPATHSIZE)
 
queuetype        bgpinfo_nlriQ;



/*
 * edt: * * bgp_extract_community
 *
 * Extract received communities and store them in a sorted order.
 *
 * Return: uint32_t
 *   The number of unique communities extracted.
 *
 * Argument: char *data
 *   IN    - Buffer containing the communities
 *
 * Argument: uint32_t count
 *   IN    - The number of communities in the buffer
 *
 * Argument: unit32_t *comm_array
 *   IN    - The array of extracted, sorted communities
 *
 * Argument: bool duplicate
 *   OUT   - TRUE: A duplicate community was encountered.
 *           FALSE: No duplicates were found.
 *
 * Argument: bool *ao
 *   OUT   - TRUE if accept-own community was present.
 */
static uint32_t
bgp_extract_community (char     *data,
                       uint32_t  count,
                       uint32_t *comm_array,
                       bool     *duplicate,
                       bool     *ao)
{
    uint32_t i;
    uint32_t comm;
    uint32_t cnt;
    uint32_t out_count;
    uint32_t index;
    bool     found;

    *duplicate = FALSE;
    *ao = FALSE;

    /*
     * Store the communities as sorted entries as it will speed the
     * exact community MATCH.
     * If same community appears twice, omit it.
     */
    out_count = 0;
    for (cnt = 0; cnt < count; cnt++, data += sizeof(uint32_t)) {

        comm = GETLONG(data);
        found = sorted_array_get_index((uint32_t *)comm_array,
                                       (int)out_count, (int *)&index,
                                       (uint32_t)comm);

        if (found) {
            *duplicate = TRUE;
        } else {
            if (comm == COMMUNITY_ACCEPT_OWN) {
                *ao = TRUE;
            }
            
            /*
             * Make room in the array for the new community
             */
            for (i = out_count; i > index; i--) {
                comm_array[i] = comm_array[i-1];
            }

            comm_array[index] = comm;
            out_count++;
        }
    }

    return (out_count);
}


/*
 * edt: * * bgp_extract_extcommunity
 *
 * Extract received extended communities and store them in sorted order.
 *
 * Return: uint32_t
 *   The number of unique communities extracted.
 *
 * Argument: bgp_nbrtype *nbr
 *   IN    - Neighbor structure
 *
 * Argument: battrtype *attr
 *   IN    - Pointer to path attribute
 *
 * Argument: char *data
 *   IN    - Buffer containing the communities
 *
 * Argument: uint32_t count
 *   IN    - The number of communities in the buffer
 *
 * Argument: unit32_t *comm_array
 *   IN    - The array into which ext communities are written
 *
 * Argument: uint32_t *battr_flags
 *   OUT   - Flags indicating what types of extended communities were received
 *
 * Argument: bool duplicate
 *   OUT   - TRUE: A duplicate community was encountered.
 *           FALSE: No duplicates were found.
 */
static uint32_t
bgp_extract_extcommunity (bgp_nbrtype *nbr,
                          battrtype   *attr,
                          bpathtype   *path,
                          char        *data,
                          uint32_t      count,
                          bgp_extcomm *comm_array,
                          uint32_t    *battr_flags,
                          bool        *duplicate)
{
    uint32_t cnt;
    uint32_t out_count;
    uint32_t index;
    uint16_t type;
    bool     found;
    uint32_t soo_count;
    uint16_t as;
    uint8_t  validity;

    *battr_flags = 0;
    *duplicate = FALSE;

    /*
     * Store the communities as sorted entries as it will speed the exac
     * exact community MATCH. Keep all SoO community in the beginning
     * of extended community array for quicker comparision during
     * update generation. Other communities are not accessed as frequently
     * as SoO.
     *
     * If same community appears twice, omit it.
     */
    out_count = 0;
    soo_count = 0;
    for (cnt = 0; cnt < count; cnt++, data += sizeof(bgp_extcomm)) {

        type = GETSHORT((bgp_extcomm *)data);

        /*
         * Ignore any non-transitive extcomms from ebgp peers. For
         * ibgp peers, consider all extcomms.
         */
        if (!(bgp_commonadmin(&nbr->nbrinfo) ||
              (EXTCOMM_TRANS(type) == BGP_EXTCOMM_TRANSITIVE))) {
            continue;
        }
        if (IS_EXTCOMMUNITY_SOO(type)) {
            found = extcomm_sorted_array_get_index(comm_array, 0, soo_count,
                                                   &index,
                                                   (bgp_extcomm *)data);
            if (!found) {
                /*
                 * book keeping for a new SoO extended community attribute
                 */
                soo_count++;
            }
        } else {
            found = extcomm_sorted_array_get_index(comm_array, soo_count,
                                                   out_count, &index,
                                                   (bgp_extcomm *)data);
        }

        if (found) {
            *duplicate = TRUE;
        } else {
            if (IS_EXTCOMMUNITY_VD(type)) {
                (void)bgp_extcomm_get_vd((bgp_extcomm *)data, &as,
                                         &(attr->vd));
                *battr_flags |= BATTR_VD_EXTCOMM;

            } else {
                memmove(&comm_array[index + 1], &comm_array[index],
                        (out_count - index) * sizeof(bgp_extcomm));

                memcpy(&comm_array[index], data, sizeof(bgp_extcomm));
                out_count++;

                if (IS_EXTCOMMUNITY_ORIGIN_VALIDATION_STATE(type)) {
                    (void)
                    bgp_extcomm_get_origin_validation_state((bgp_extcomm *)data, 
                                                             &validity);

                    bpath_set_origin_as_validity(path, validity, FALSE);

                    *battr_flags |= BATTR_VALIDITY;

                } else if (IS_EXTCOMMUNITY_SOO(type)) {
                    *battr_flags |= BATTR_SOO_EXTCOMM;
                } else if (IS_EXTCOMMUNITY_RT(type)) {
                    *battr_flags |= BATTR_RT_EXTCOMM;
                } else if (IS_EXTCOMMUNITY_IGP(type)) {
                    *battr_flags |= BATTR_IGP_EXTCOMM;
                } else if (IS_EXTCOMMUNITY_LB(type)) {
                    *battr_flags |= BATTR_DMZLINK_EXTCOMM;
                } else if (IS_EXTCOMMUNITY_COST(type)) {
                    *battr_flags |= BATTR_COST_EXTCOMM;
                } else if (IS_EXTCOMMUNITY_L2VPN(type)) {
                    *battr_flags |= BATTR_L2VPN_EXTCOMM;
                }  else if (IS_EXTCOMMUNITY_VRF_ROUTE_IMPORT(type)) {
                    *battr_flags |= BATTR_VRF_ROUTE_IMPORT_EXTCOMM;
                } else {
                    *battr_flags |= BATTR_UNKNOWN_EXTCOMM;
                }
            }
        }
    }

    return (out_count);
}


/*
 * bgp4_rcv_v4withdrawn
 *
 * EDT in bgp_util.h
 */
static void
bgp4_rcv_v4withdrawn (bgp_nbrtype       *nbr,
                      uint8_t           *msg,
                      uint16_t           msg_len,
                      uint8_t           *ipv4_wdr_data,
                      uint16_t           ipv4_wdr_len)
{
    bnlritype              *bgp_nlri = NULL;

    // Just return if no data
    if (ipv4_wdr_len == 0) {
        return;
    }

    // Do nothing if IPv4-Unicast is not applicable
    if (!bgp4_rcv_afi_is_acceptable(nbr, BGP_TYPE_UPDATE,
                                    BGP_AF_IPv4,
                                    BGP_IPv4_ADDRESS_FAMILY, BGP_SAF_UNICAST,
                                    "IPv4 Withdrawn Routes", error_ttylist)) {
        return;
    }

    bgp_nlri = bnlri_alloc();

    if (bgp_nlri == NULL) {
        (void) bgp_upd_err_handle(nbr, msg, msg_len,
                                  BGP_UPD_ERR_C1_MEM_ALLOC_FAIL,
                                  0, 0, 0,
                                  NULL, 0);
        bgp_upd_err_store_reset_data(nbr,
                                     BGP_NOMEMORY,
                                     BGP_POSTIT_TYPE_NOMEMORY,
                                     0, 0, NULL, 0);
        ios_msg_bgp_nomem_reset("Withdrawn NLRI");
        //***bgp_reset(BGP_NBR_TO_VRF(bgp), bgp, BGP_NOMEMORY,
                  //***BGP_POSTIT_TYPE_NOMEMORY);
        return;
    }

    bgp_nlri->code = BGP_UNREACHABLE_NLRI;

    bgp_nlri->afi = BGP_AF_IPv4;
    bgp_nlri->rcvd_afi = BGP_IPv4_ADDRESS_FAMILY;
    bgp_nlri->rcvd_safi = BGP_SAF_UNICAST;
    bgp_nlri->nlri = ipv4_wdr_data;
    bgp_nlri->len = ipv4_wdr_len;

    queue_enqueue(&bgpinfo_nlriQ, bgp_nlri);

    return;
}


/*
 * bgp4_rcv_buffer_init
 *
 * EDT in bgp_util.h
 */
void
bgp4_rcv_buffer_init (bgp_nbrtype     *bgp,
                      bpathtype       *path,
                      bgp_tblattrtype *mtblattr)
{
    battrtype    *mattr;

    if (bgp == NULL) {
        return;
    }

    mattr = mtblattr->attr;
    memset(mattr, 0, sizeof(battrtype));

    /*
     * No need to initialize the entire buffer space since valid index
     * delimited by the number of entries is used to access the buffer
     */
    memset(bgprtr_msg_rrinfobuf, 0, sizeof(brrinfotype));
    memset(bgprtr_msg_nexthopbuf, 0, BNEXTHOP_MAX_SIZE);
    memset(bgprtr_msg_aspathbuf, 0, sizeof(baspathtype));
    memset(bgprtr_msg_new_aspathbuf, 0, sizeof(baspathtype));
    memset(bgprtr_msg_combuf, 0, sizeof(bcommtype));
    memset(bgprtr_msg_extcommbuf, 0, sizeof(bextcommtype));
    memset(bgprtr_msg_ssabuf, 0, sizeof(bssatype));
    memset(bgprtr_msg_connbuf, 0, sizeof(bconntype));
    memset(bgprtr_msg_pmsibuf, 0, sizeof(bpmsitype));
    memset(bgprtr_msg_ppmpbuf, 0, sizeof(bppmptype));

    mattr->aspathptr = bgprtr_msg_aspathbuf;
    mattr->new_aspathptr = bgprtr_msg_new_aspathbuf;
    mattr->commptr = bgprtr_msg_combuf;
    mattr->extcommptr = bgprtr_msg_extcommbuf;
    mattr->ssaptr = bgprtr_msg_ssabuf;
    mattr->connptr = bgprtr_msg_connbuf;
    mattr->pmsiptr = bgprtr_msg_pmsibuf;
    mattr->ppmpptr = bgprtr_msg_ppmpbuf;

    /*
     * Prepare the path stucture to receive update.  Set the pathinfo
     * flag to indicate if the path is from RR client or from
     * confederation peer.
     */
    bgp_path_init(path, bgp_info.max_path_size);
    path->nbrinfo = &(bgp->nbrinfo);
    path->iid = bgp_info.sn_process_id;
    path->bp_flags |= BPATH_VALID;
    path->tblattr = mtblattr;
    path->rrinfo = bgprtr_msg_rrinfobuf;
    path->nexthop = bgprtr_msg_nexthopbuf;
    if (bgp->cfg.is_internal) {
        path->bp_flags |= BPATH_INTERNAL;
    }
    if ((bgp_info.confed_id != 0) &&
        (bgp->nbrinfo.nbrinfo_flags & BNBRINFO_NBR_COMMONADMIN)) {
        path->bp_flags |= BPATH_CONFED;
    }
}


/*
 * bgp4_rcv_attr_flag
 *
 */
static void
bgp4_rcv_attr_flag (bgp_nbrtype *nbr,
                    uint8_t *msg,
                    uint16_t msg_len,
                    uint16_t ipv4_reach_len,
                    uint8_t **rcv_data,
                    uint16_t *rcv_len,
                    uint8_t **errptr,
                    uint16_t *errlen,
                    uint8_t *attr_flags,
                    uint8_t *attr_code,
                    uint16_t *attr_len,
                    uint8_t **attr_data,
                    uint8_t *filter_action,
                    bgp_upd_err_action_t *err_action,
                    bgp_dbg_ttylist *error_ttylist)
{
    uint8_t                     bnot_error = 0;
    uint8_t                     hdrbytes = 0;

    //bgp_debug_ttyprintf(error_ttylist,
                     //"--%s--: nbr=%s:: rcvdata=0x%08x/%u, errptr=0x%08x/%u",
                     //__FUNCTION__,
                     //nbr->neighbor_name,
                     //(uint32_t)*rcv_data, *rcv_len,
                     //(uint32_t)*errptr, *errlen);

    /*
     * By default, set the errlen for NOTIFICATION to be all the
     * remaining bytes.  If we successfully read the attribute length
     * then this will be updated to only include the attribute.
     */
    *errptr = *rcv_data;
    *errlen = *rcv_len;

    /*
     * Read the attribute flags and attribute type code from the message,
     * and update the size of the remaining path attribute data to reflect
     * that the flags and code have been read.
     */
    if (*rcv_len >= 2) {

        *attr_flags = (**rcv_data);
        (*rcv_data)++;
        *attr_flags &= UPF_USED;

        *attr_code = (**rcv_data);
        (*rcv_data)++;
        *rcv_len -= 2;
        hdrbytes += 2;
    } else {
        bnot_error = BNOT_UPDATE_MALFORMED;
    }

    if (bnot_error == 0) {
        *filter_action = bgp_upd_filter_attr_filter(nbr, msg, msg_len,
                                                    *attr_flags, *attr_code);

        // Note: We have to continue parsing the rest of the attribute
        // header in order to find the attribute length if filtering
        // indicates:
        //   discard-attribute
        // -OR-
        //   treat-as-withdraw - NLRIs have not yet been encountered

        if (*filter_action == BGP_UPD_FILTER_ACTION_WDR) {
            if ((ipv4_reach_len > 0) || (!queue_empty(&bgpinfo_nlriQ))) {
                *rcv_len = 0;
                *errlen = 0;
                *attr_len = 0;

                return;
            }
        }
    }

    if (bnot_error == 0) {
        if ((*attr_flags & UPF_EXTENDED) != 0) {
            *attr_flags &= ~UPF_EXTENDED;

            /*
             * The extended length bit is set in the attribute flags, so the
             * attribute length field is two octets in size. Update the
             * size of the remaining path attribute data to reflect that the
             * length field has been read.
             */
            if (*rcv_len >= 2) {
                *attr_len = GETSHORT(*rcv_data);
                *rcv_data += sizeof(uint16_t);
                *rcv_len -= 2;
                hdrbytes += 2;
            } else {
                bnot_error = BNOT_UPDATE_MALFORMED;
            }
        } else {

            /*
             * The extended length bit is not set, so the attribute length
             * field is one octet in size. Update the size of the remaining
             * path attribute data to reflect that the length field has been
             * read.
             */
            if (*rcv_len >= 1) {
                *attr_len = (**rcv_data);
                *rcv_data += 1;
                *rcv_len -= 1;
                hdrbytes++;
            } else {
                bnot_error = BNOT_UPDATE_MALFORMED;
            }
        }
    }

    if (bnot_error == 0) {
        if (*rcv_len < *attr_len) {
            bnot_error = BNOT_UPDATE_MALFORMED;
        }
    }

    if (bnot_error == 0) {
        *attr_data = *rcv_data;
        *rcv_data += *attr_len;
        *rcv_len -= *attr_len;

        *errlen = *attr_len + hdrbytes;
    } else {
        bgp_debug_ttyprintf(error_ttylist,
                            "Malformed Update attr from %s: Attr flags=0x%02x, "
                            "code=%u, len=%u:: rcvdata=0x%08x, rcvlen=%u, "
                            "errdata=0x%08x, errlen=%u, hdrlen=%u",
                            nbr->neighbor_name,
                            *attr_flags, *attr_code, *attr_len,
                            (uint32_t)*rcv_data, *rcv_len, (uint32_t)*errptr,
                            *errlen, hdrbytes);
        *err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                         BGP_UPD_ERR_C2_ATTR_LEN_INCONST,
                                         *attr_flags, *attr_code, *attr_len,
                                         *errptr, 4);
        bgp_upd_err_store_reset_data(nbr,
                                     BGP_NONE,
                                     BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                     BNOT_UPDATE, bnot_error,
                                     *errptr, 4);

        *rcv_len = 0;
        *errlen = 0;
        *attr_len = 0;
    }

    //bgp_debug_ttyprintf(error_ttylist,
                     //"----%s: nbr=%s:: rcvdata=0x%08x/%u, errptr=0x%08x/%u: "
                     //"attrfl=0x%02x, attrcode=%u, attrlen=%u, "
                     //"attrdata=0x%08x: filteraction=%u",
                     //__FUNCTION__,
                     //nbr->neighbor_name,
                     //(uint32_t)*rcv_data, *rcv_len,
                     //(uint32_t)*errptr, *errlen,
                     //*attr_flags, *attr_code, *attr_len,
                     //(uint32_t)*attr_data, *filter_action);

    return;
}


/*
 * bgp4_rcv_attr_len_zero
 *
 */
static bgp_upd_err_action_t
bgp4_rcv_attr_len_zero (bgp_nbrtype *nbr,
                        uint8_t *msg,
                        uint16_t msg_len,
                        uint8_t *errptr,
                        uint16_t errlen,
                        uint8_t attr_flags,
                        uint8_t attr_code,
                        uint16_t attr_len,
                        bgp_dbg_ttylist *error_ttylist)
{
    bgp_upd_err_action_t    err_action = BGP_UPD_ERR_ACTION_NONE;
    bool                    valid = FALSE;

    if (attr_len != 0) {
        return (BGP_UPD_ERR_ACTION_NONE);
    }

    // Check which attributes may or may not have a zero length data
    switch (attr_code) {
        case ATT4_ORIGIN:
        case ATT4_NEXTHOP:
        case ATT4_EXITDISC:
        case ATT4_LOCALPREF:
        case ATT4_AGGREGATOR:
        case ATT4_COMMUNITY:
        case ATT4_EXTCOMM:
        case ATT4_CLUSTLIST:
        case ATT4_ORIGINATOR:
        case ATT4_SSA:
        case ATT4_CONNECTOR:
        case ATT4_PMSI:
        case ATT4_PPMP:
        case ATT4_MP_REACH_NLRI:
        case ATT4_MP_UNREACH_NLRI:
        case ATT4_NEW_AGGREGATOR:
        case ATT4_AIGP:
            valid = FALSE;
            break;

        case ATT4_PATH:
        case ATT4_NEW_ASPATH:
        case ATT4_ATOMICAGG:
        default:
            valid = TRUE;
            break;
    }

    // Perform error-handling if zero length is not expected
    if (!valid) {
        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                        (attr_code == ATT4_NEXTHOP ?
                                           BGP_UPD_ERR_C4_NH_LEN_0 :
                                           BGP_UPD_ERR_C4_ATTR_LEN_0),
                                        attr_flags, attr_code, attr_len,
                                        errptr, 4);
        bgp_upd_err_store_reset_data(nbr,
                                     BGP_NONE,
                                     BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                     BNOT_UPDATE, BNOT_UPDATE_LENGTH,
                                     errptr, 4);
    }

    return (err_action);
}


/*
 * bgp4_rcv_origin -
 *
 * Parse BGP4 origin attribute.
 */
static void
bgp4_rcv_origin (bgp_nbrtype     *nbr,
                 uint8_t         *msg,
                 uint16_t         msg_len,
                 uint8_t         *errptr,
                 uint16_t         errlen,
                 uchar_t         *data,
                 ushort_t         len,
                 uchar_t          flags,
                 bpathtype       *rpath,
                 bgp_dbg_ttylist *error_ttylist)
{
    bgp_upd_err_action_t    err_action = BGP_UPD_ERR_ACTION_NONE;
    battrtype              *rattr = NULL;

    if (flags != UPF_TRANSIT) {
        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                        BGP_UPD_ERR_C4_ATTR_FLAGS_INVALID,
                                        flags, ATT4_ORIGIN, len,
                                        errptr, 3);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    rattr = BGP_PATH_TO_ATTR(rpath);
    if (rattr == NULL) {
        return;
    }

    if (rattr->flags & BATTR_ORIGIN) {
        bgp_debug_ttyprintf(error_ttylist,
                            "UPDATE from %s contains duplicate ORIGIN "
                            "attribute",
                            nbr->neighbor_name);

        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                        BGP_UPD_ERR_C3_ATTR_NON_OPTR_DUPLICATE,
                                        flags, ATT4_ORIGIN, len,
                                        errptr, 3);
        bgp_upd_err_store_reset_data(nbr,
                                     BGP_NONE,
                                     BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                     BNOT_UPDATE, BNOT_UPDATE_MALFORMED,
                                     errptr, errlen);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    if (len != 1) {
        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                      BGP_UPD_ERR_C2_ATTR_NON_OPTR_LEN_INVALID,
                                        flags, ATT4_ORIGIN, len,
                                        errptr, 3);
        bgp_upd_err_store_reset_data(nbr,
                                     BGP_NONE,
                                     BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                     BNOT_UPDATE, BNOT_UPDATE_LENGTH,
                                     errptr, 3);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    rattr->origin = *data;
    if (rattr->origin > ORIGIN_INCOMPLETE) {
        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                     BGP_UPD_ERR_C2_ATTR_NON_OPTR_DATA_INVALID,
                                        flags, ATT4_ORIGIN, len,
                                        errptr, errlen);
        bgp_upd_err_store_reset_data(nbr,
                                     BGP_NONE,
                                     BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                     BNOT_UPDATE, BNOT_UPDATE_ORIGIN,
                                     errptr, errlen);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    rattr->flags |= BATTR_ORIGIN;

    return;
}


/*
 * bgp_pathvalid
 *
 * Validate this BGP4 style AS path. Point to path (of len bytes).
 */
static bool
bgp_pathvalid (bgp_nbrtype     *nbr,
               uchar_t         *path,
               ushort_t         len,
               bool             new_aspath,
               bgp_dbg_ttylist *error_ttylist,
               bool            *remove_confed)
{
    uchar_t         seglen;                   /* number of segments       */
    ushort_t        segbytes;                 /* segment length in bytes  */
    uchar_t         segtype;                  /* segment type             */
    char            as_buf1[ASCII_ASNUMSIZE]; /* AS buffer                */
    char            as_buf2[ASCII_ASNUMSIZE]; /* AS buffer                */
    uint32_t        asnum;                    /* AS number                */

    if (nbr == NULL) {
        return (FALSE);
    }

    /*
     * The new_aspath must contain atleast one AS number. This is true for
     * both internal and external neighbors.
     */
    if (new_aspath) {
        if (len < EBGP_ASPATH_MIN) {
            bgp_debug_ttyprintf(error_ttylist,
                                "new_aspath has invalid length %u,"
                                " must be at least %u", len, EBGP_ASPATH_MIN);
            return (FALSE);
        }
    }

    /*
     * Do EBGP validations on the aspath. This is not applicable for
     * new_aspath.
     */
    if ((!new_aspath) && (nbr->cfg.is_internal == FALSE)) {
        if (len < EBGP_ASPATH_MIN) {
            bgp_debug_ttyprintf(error_ttylist, "aspath has invalid length %u,"
                                " must be at least %u", len, EBGP_ASPATH_MIN);
            return (FALSE);
        }

        if (bgp_nbr_is_enforce_first_as(nbr) &&
            (nbr->nbrinfo.nbrinfo_flags & BNBRINFO_NBR_COMMONADMIN) == 0) {

            asnum = GETLONG(path + ASPATH_SEGMENT_OVERHEAD);
            if (nbr->cfg.yoursystem != asnum) {
                (void)bgp_util_asn_print(as_buf1, sizeof(as_buf1),
                                         0, asnum);
                (void)bgp_util_asn_print(as_buf2, sizeof(as_buf2),
                                         0, nbr->cfg.yoursystem);
                bgp_debug_ttyprintf(error_ttylist, "aspath first AS is %s, "
                                    "not %s", as_buf1, as_buf2);
                return (FALSE);
            }
        }
    }

    for (; len >= ASPATH_SEGMENT_OVERHEAD; len -= ASPATH_SEGMENT_OVERHEAD) {
        segtype = *path++;
        seglen = *path++;
        segbytes = (seglen * ASPATHSIZE);

        switch(segtype) {
        case AS_CONFED_SEQUENCE:
        case AS_CONFED_SET:
            if (!new_aspath) {
                if (!bgp_commonadmin(&nbr->nbrinfo)) {
                    bgp_debug_ttyprintf(error_ttylist, "aspath from an external "
                                        "peer has an %s segment",
                                        segtype == AS_CONFED_SEQUENCE ?
                                        "AS_CONFED_SEQUENCE" : "AS_CONFED_SET");
                    *remove_confed = TRUE;
                }
            } else {
                *remove_confed = TRUE;
            }
            /* sa_ignore FALL_THRU */

        case AS_SET:
        case AS_SEQUENCE:
            if (seglen == 0) {
                bgp_debug_ttyprintf(error_ttylist, "aspath segment length "
                                    "is %u", seglen);
                return (FALSE);
            }
            if (segbytes > (len - ASPATH_SEGMENT_OVERHEAD)) {
                bgp_debug_ttyprintf(error_ttylist, "aspath has invalid segment"
                                    " bytes %u, maximum is %u", segbytes,
                                    len - ASPATH_SEGMENT_OVERHEAD);
                return (FALSE);
            }

            len  -= segbytes;
            path += segbytes;
            break;

        default:
            bgp_debug_ttyprintf(error_ttylist, "unknown segment type %u",
                                segtype);
            return (FALSE);
        }
    }

    return (len == 0);
}


/*
 * bgp_aspath_find_new_aspath_segment
 *
 * Find the new aspath segment with the matching segment type.
 *
 * Return: uchar_t *
 *          Return the starting address of the segment in the new aspath which
 *          matches the segment type passed in.
 *
 * Argument: uchar_t *new_aspath
 *   IN    - new aspath pointer
 *
 * Argument: uint16_t *new_aspathlen
 *   IN    - new aspath length
 *
 * Argument: uint16_t *segtype
 *   IN    - the 2byte aspath segment type to match against.
 */
static uchar_t *
bgp_find_new_aspath_segment (uchar_t *new_aspath, uint16_t *new_aspathlen,
                             uint16_t segtype)
{
    uchar_t        *cpi;                 /* temporary pointer to aspath      */
    uchar_t        *segstart;            /* pointer to the segment start     */
    uint16_t        ix;                  /* Index                            */
    int16_t         seglen_byte;         /* segment length                   */
    int16_t         aspathlen;           /* aspath length                    */

    if (!new_aspath || !new_aspathlen) {
        return (NULL);
    }

    aspathlen = *new_aspathlen;

    for (cpi = new_aspath, ix = aspathlen; ix > 0; ix -= 2) {
        segstart = cpi;
        /*
         * Look for the first matching segment only and skip over those
         * segments which do not match
         */
        switch (*cpi++) {
        case AS_SET:
        case AS_SEQUENCE:
        case AS_CONFED_SEQUENCE:
        case AS_CONFED_SET:
            if (*segstart == segtype) {
                *new_aspathlen -= segstart - new_aspath;
                return (segstart);
            }
            seglen_byte = *cpi++ * ASPATHSIZE;
            cpi += seglen_byte;
            ix -= seglen_byte;
            break;
        default:
            return (NULL);
        }
    }
    return (NULL);
}

/*
 * bgp_pathbuf_copy
 *
 * Copy the specified number of bytes from source buffer to the
 * destination buffer. Also Increment the destination length and destination
 * buffer pointer by those number of bytes.
 *
 * Return: void
 *
 * Argument: uchar_t **dst
 *   IN    - pointer to destination buffer
 *
 * Argument: uchar_t *src
 *   IN    - pointer to source buffer
 *
 * Argument: uint16_t len
 *   IN    - number of bytes to copy from the source to the destination

 * Argument: uint16_t *dst_len
 *   IN    - destination length. This will be incremented by 'len'.
 */
static void
bgp_pathbuf_copy (uchar_t **dst, uchar_t *src, int16_t len,
                  int16_t *dst_len)
{
    memcpy(*dst, src, len);
    *dst_len += len;
    *dst += len;
}

/*
 * bgp_merge_new_aspath
 *
 * Merge AS_PATH and NEW_ASPATH attributes into a combined aspath structure.
 *
 * According to RFC 4893, to construct the aspath information, first
 * calculate pathlength in the AS_PATH and NEW_ASPATH attributes.  If
 * pathlength in AS_PATH is less than NEW_ASPATH, then ignore NEW_ASPATH.
 *
 * If the pathlength of AS_PATH is larger or equal to NEW_ASPATH, then
 * we take as many AS numbers and path segments as necessary from the
 * leading part of the AS_PATH attribute, and then prepend them to the
 * NEW_ASPATH attribute so that the newly constructed AS_PATH attribute
 * has the identical number of ASes as the earlier AS_PATH attribute.
 *
 * Note that a valid AS_CONFED_SEQUENCE or AS_CONFED_SET path segment
 * SHALL be prepended if they is either the leading path segment or
 * adjacent to a path segment that is prepended.
 *
 * Return: bool
 *         TRUE if no errors were encountered during the merge,
 *         FALSE otherwise.
 *
 * Argument: battrtype *rattr
 *   IN    - Pointer to path attribute
 *
 * Argument: bgp_dbg_ttylist *error_ttylist
 *   IN    - List of ttys for debug messages when errors are encountered.
 */
static void
bgp_merge_new_aspath (bgp_nbrtype     *bgp,
                      battrtype       *rattr,
                      bgp_dbg_ttylist *error_ttylist)
{
    uchar_t        *cpi;                  /* temporary pointer to aspath  */
    uchar_t        *new_aspath;           /* pointer to the new aspath    */
    uchar_t        *new_aspath_segstart;  /* ptr to the new aspath segment*/
    uchar_t        *aspath_merge_pathbuf; /* ptr to the merged aspath     */
    uchar_t        *mergedpath;           /* pointer to the merged aspath */
    uchar_t        *segstart;             /* pointer to the segment start */
    uchar_t        *seglen_ptr;           /* segment length pointer       */
    int16_t         ix;                   /* Index                        */
    int16_t         len;                  /* temporary aspath length      */
    int16_t         aspathlen;            /* aspath length                */
    int16_t         seglen;               /* segment length               */
    uint16_t        segtype;              /* segment type                 */
    int16_t         new_aspathlen;        /* new aspath length            */
    uint16_t        new_aspath_segtype;   /* new aspath segment type      */
    int16_t         new_aspath_seglen;    /* new aspath segment len       */
    int16_t         aspath_merge_pathlen; /* megred aspath length         */
    int32_t         num_leading_pathseg;  /* number of leading AS numbers
                                           * in 2byte vs 4byte aspath     */
    baspathtype    *aspathptr;            /* ASPATH baspathtype           */
    baspathtype    *new_aspathptr;        /* NEW_ASPATH baspathtype       */
    int32_t        old_hopcount;          /* hopcount for old aspath      */
    int32_t        new_hopcount;          /* hopcount for new aspath      */


    aspathptr = rattr->aspathptr;
    aspathlen = aspathptr->aslength;

    new_aspathptr = rattr->new_aspathptr;
    new_aspath    = new_aspathptr->aspath;
    new_aspathlen = new_aspathptr->aslength;

    old_hopcount = ip_bgp_aspath_hopcount(aspathptr->aspath, aspathlen, FALSE, NULL);
    new_hopcount = ip_bgp_aspath_hopcount(new_aspath, new_aspathlen, FALSE, NULL);

    /*
     * Just in case.
     */
    if ((old_hopcount < 0) || (new_hopcount < 0)) {
        return;
    }

    /*
     * Ignore the NEW_ASPATH if pathlength in AS_PATH is less than NEW_ASPATH
     */
    num_leading_pathseg = old_hopcount - new_hopcount;
    if (num_leading_pathseg < 0) {
        return;
    }

    /*
     * Do not bother with merging if the attributes are super long.
     *
     * The simplistic approach here does not quite match with the merge
     * algorithm, but it should be good enough in practice.
     */
    if ((aspathlen + new_aspathlen) > BGP_RCV_ASPATH_MAXLEN) {
        bgp_debug_ttyprintf(error_ttylist,
                            "AS_PATH length (%d) and AS4_PATH length (%d)"
                            " are too large, skip AS4_PATH",
                            aspathlen, new_aspathlen);
        return;
    }

    aspath_merge_pathbuf = bgprtr_merge_aspathbuf;
    aspath_merge_pathlen = 0;
    mergedpath = bgprtr_merge_aspathbuf;

    /*
     * Look for the leading segments in aspath and prepend them to the
     * NEW_ASPATH attribute
     */
    for (cpi = aspathptr->aspath, ix = aspathlen; ix > 0; ix -= 2) {
        segstart = cpi;
        segtype = *cpi++;
        seglen = *cpi++;

        switch (segtype) {
        case AS_SET:
            /*
             * Done with as-path when no more leading ASes are found
             */
            if (!num_leading_pathseg) {
                goto copy_new_aspath;
            }

            len = seglen * ASPATHSIZE;
            /*
             * Copy the entire leading part of as_set from ASPATH
             */
            bgp_pathbuf_copy(&aspath_merge_pathbuf, segstart, len+2,
                             &aspath_merge_pathlen);
            num_leading_pathseg--;
            cpi += len;
            ix -= len;
            continue;

        case AS_SEQUENCE:
            /*
             * Done with as-path when no more leading ASes are found
             */
            if (!num_leading_pathseg) {
                goto copy_new_aspath;
            }

            /*
             * Copy each ASN from the entire leading part of as_seq from
             * ASPATH and append the rest (nonzero seglen) from NEW_ASPATH
             */
            aspath_merge_pathlen += 2;
            *aspath_merge_pathbuf++ = segtype;
            seglen_ptr = aspath_merge_pathbuf;
            *aspath_merge_pathbuf++ = seglen;

            for (; (seglen > 0) && (ix > 0) && num_leading_pathseg &&
                     (aspath_merge_pathbuf < &mergedpath[BGP_ASPATHBUFLEN]);
                 seglen--, ix -= ASPATHSIZE, cpi += ASPATHSIZE) {

                bgp_pathbuf_copy(&aspath_merge_pathbuf, cpi, ASPATHSIZE,
                                 &aspath_merge_pathlen);
                num_leading_pathseg--;
            }

            /*
             * Move onto the next segment if we consumed this entire segment
             * (leading part is likely nonzero)
             */
            if (!seglen) {
                continue;
            }

            len = seglen * ASPATHSIZE;
            cpi += len;
            ix -= len;

            /*
             * Replace AS_PATH with NEW_ASPATH for rest of the as_seq.
             * This is to ensure we merge with 1st as_seq in NEW_ASPATH
             */
            new_aspath = bgp_find_new_aspath_segment(new_aspath,
                                                     &new_aspathlen,
                                                     segtype);
            if (new_aspath) {
                new_aspath_segstart = new_aspath;
                new_aspath_segtype = *new_aspath++;
                new_aspath_seglen = *new_aspath++;

                /*
                 * replace the rest of the as_seq segment with the new_aspath
                 * segment if the new_aspath has the same length remaining
                 * e.g AS_PATH    = 200 23456 44
                 *     NEW_ASPATH = 1.1 44
                 * We want to append NEW_ASPATH 1.1 44 after 200
                 */
                if (new_aspath_seglen == seglen) {

                    len = new_aspath_seglen * ASPATHSIZE;
                    bgp_pathbuf_copy(&aspath_merge_pathbuf, new_aspath, len,
                                     &aspath_merge_pathlen);
                    new_aspath += len;
                    new_aspathlen -= len + 2;
                } else {
                    /*
                     * To handle multi AS_SEQ segments:
                     * AS_PATH = AS_SEQ 100 200 AS_SEQ 300 23456 500
                     * NEW_ASPATH = AS_SEQ 200 300 AS_SEQ 4.44 500
                     * in this case, after copying over 100 from aspath,
                     * the remaining segment length (1 in this example)
                     * would *not* match up with seglen of NEW_ASPATH. So,
                     * we simply rollback to beginning of new aspath and
                     * append to the merge buffer after the leading part.
                     *   Merged aspath is ...
                     * AS_SEQ 100 AS_SEQ 200 300 AS_SEQ 4.44 500
                     */
                    *seglen_ptr -= seglen;
                    new_aspath = new_aspath_segstart;
                }
            }

            /*
             * proceed to merging remaining part of NEW_ASPATH
             */
            goto copy_new_aspath;

        case AS_CONFED_SEQUENCE:
        case AS_CONFED_SET:
            /*
             * prepend confed segments appear in the leading part of aspath
             */
            len = seglen * ASPATHSIZE;
            bgp_pathbuf_copy(&aspath_merge_pathbuf, segstart, len+2,
                            &aspath_merge_pathlen);
            cpi += len;
            ix -= len;
            continue;

        default:
            break;
        }
    }

copy_new_aspath:

    /* 
     * If the new_aspath is NULL, it means that there was a problem 
     * with the merge, viz. segment types did not match, so we can just
     * discard the new_aspath and return TRUE here
     */
    if (new_aspath == NULL) {
        bgp->aspath_as4path_merge_prob++;
        ios_msg_bgp_inconsistent_aspathmerge(bgp->neighbor_name,
                                             "Ignore AS4_PATH in merge");
        return;
    }
    
    bgp_pathbuf_copy(&aspath_merge_pathbuf, new_aspath, new_aspathlen,
                     &aspath_merge_pathlen);
    /*
     * Just take the AS_PATH in case the pathlength of AS_PATH and
     * NEW_ASPATH dont match up (that is, there is an error in merging).
     */
    if (ip_bgp_aspath_hopcount(aspathptr->aspath, aspathlen, FALSE, NULL) !=
        ip_bgp_aspath_hopcount(bgprtr_merge_aspathbuf,
                               aspath_merge_pathlen, FALSE, NULL)) {

        bgp_debug_ttyprintf(error_ttylist,
                            "Mismatch in AS_PATH length (%d) and NEW_ASPATH"
                            " length (%d)", aspathlen, aspath_merge_pathlen);
        return;
    }

    memcpy(aspathptr->aspath, bgprtr_merge_aspathbuf, aspath_merge_pathlen);
    aspathptr->aslength = aspath_merge_pathlen;

    return;
}


/*
 * bgp4_remove_confed_from_aspath
 *
 * The NEW_ASPATH attribute must not contain any type of confed segments.
 * The ASPATH attribute from a true EBGP peer may not contain any confed
 * segment either. Remove any confed segment that exists in the rcvd ASPATH
 * or NEW_ASPATH attribute. Adjust the length of the rcvd ASPATH or
 * NEW_ASPATH attribute accordingly.
 *
 * Return: ushort
 *         The adjusted length of the ASPATH or NEW_ASPATH attribute.
 *
 * Argument: uchar_t *aspath
 *   IN    - Pointer to rcvd ASPATH or NEW_ASPATH attribute
 *
 * Argument: ushort_t aspathlen
 *   IN    - The aspathlength for rcvd ASPATH or NEW_ASPATH attribute
 *
 * Argument: uchar_t *pathptr
 *   IN    - Pointer to the buffer which will contain the modified ASPATH
 *           or NEW_ASPATH attribute (after removing all the confed segments)
 */
static ushort_t
bgp4_remove_confed_from_aspath (uchar_t *aspath, ushort_t aspathlen,
                                uchar_t *pathptr)
{
    uchar_t         seg_type;            /* segment type                 */
    uchar_t         seg_cnt;             /* number of ASes in this segment */
    ushort_t        seg_len;             /* segment length               */
    ushort_t        mod_aspathlen;       /* modified aspath length       */
    ushort_t        len;                 /* temporary aspath length      */

    len = aspathlen;
    mod_aspathlen = 0;

    for (; len > 0; ) {
        seg_type = *aspath++;    /* aspath segment type */
        seg_cnt = *aspath++;     /* number of segments  */

        switch (seg_type) {
        case AS_SET:
        case AS_SEQUENCE:
            *pathptr++ = seg_type;
            *pathptr++ = seg_cnt;

            seg_len = seg_cnt * ASPATHSIZE;
            memcpy(pathptr, aspath, seg_len);
            aspath += seg_len;
            pathptr += seg_len;

            len -= (seg_len + ASPATH_SEGMENT_OVERHEAD);
            mod_aspathlen += (seg_len + ASPATH_SEGMENT_OVERHEAD);
            break;

        case AS_CONFED_SEQUENCE:
        case AS_CONFED_SET:
            /*
             * Skip over the confed segments in the NEW_ASPATH
             */
            seg_len = seg_cnt * ASPATHSIZE;
            aspath += seg_len;
            len -= (seg_len + ASPATH_SEGMENT_OVERHEAD);
            break;

        default:
            /*
             * We should never reach this because we have already
             * validated the aspath in bgp_pathvalid();
             */
            break;
        }
    }

    return (mod_aspathlen);
}


/*
 * bgp4_aspath_data_invalid
 *
 */
static void
bgp4_aspath_data_invalid (bgp_nbrtype *nbr,
                          uint8_t *msg,
                          uint16_t msg_len,
                          uint8_t *errptr,
                          uint16_t errlen,
                          uint8_t attr_flags,
                          uint8_t attr_code,
                          uint16_t attr_len,
                          battrtype *rattr)
{
    bgp_upd_err_action_t    err_action = BGP_UPD_ERR_ACTION_NONE;
    uint32_t                err_flag = 0;

    if (attr_code == ATT4_PATH) {
        err_flag = BGP_UPD_ERR_C2_ATTR_NON_OPTR_DATA_INVALID;
    } else {
        err_flag = BGP_UPD_ERR_C4_ATTR_OPTR_DATA_INVALID;

        rattr->flags &= ~BATTR_NEW_ASPATH;
        if (rattr->new_aspathptr != NULL) {
            rattr->new_aspathptr->aslength = 0;
            rattr->new_aspathptr->aspath = NULL;
        }
    }

    err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                    err_flag,
                                    attr_flags, attr_code, attr_len,
                                    errptr, errlen);
    bgp_upd_err_store_reset_data(nbr,
                                 BGP_NONE,
                                 BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                 BNOT_UPDATE, BNOT_UPDATE_BADPATH,
                                 errptr, errlen);

    return;
}


/*
 * bgp4_rcv_aspath -
 *
 * Parse BGP4 aspath attribute.
 * CLEANUP: The ILLEGAL bit need not be present in the path flags. It is a
 * transient thing, so we can just get away with it by using a local variable.
 */
static void
bgp4_rcv_aspath (bgp_nbrtype     *nbr,
                 uint8_t         *msg,
                 uint16_t         msg_len,
                 uint8_t         *errptr,
                 uint16_t         errlen,
                 uchar_t         *data,
                 ushort_t         len,
                 uchar_t          flags,
                 bpathtype       *rpath,
                 uchar_t         *myas_count,
                 uint32_t        *attr_wdr_flags,
                 bool             new_aspath,
                 bool             asloop_check,
                 bgp_dbg_ttylist *error_ttylist)
{
    bgp_upd_err_action_t    err_action = BGP_UPD_ERR_ACTION_NONE;
    battrtype              *rattr = NULL;
    bgp_vrfctxtype         *vrf_ctx = NULL;
    uint8_t                 attr_code = 0;
    uchar_t           *pathptr, *aspath;
    ushort_t           aspathlen;
    baspathtype        baspath;
    baspathtype       *raspathptr;
    bool               nbr_4byte_as_cap;
    uint16_t           convert_len;
    uint16_t           seg_cnt;
    uchar_t           *mod_aspathptr;
    ushort_t           mod_aspathlen;      /* modified aspath length */
    bool               remove_confed_from_aspath;
    uint32_t           nbr_local_as;

    vrf_ctx = BGP_NBR_TO_VRF(nbr);
    nbr_4byte_as_cap = ((nbr->flags & BN_4BYTE_AS) != 0);
    attr_code = (new_aspath ? ATT4_NEW_ASPATH : ATT4_PATH);

    if (new_aspath && nbr_4byte_as_cap) {
        bgp_debug_ttyprintf(error_ttylist,
                            "Ignoring NEW_ASPATH attribute from %s (a 4-byte "
                            "AS capable peer)",
                            nbr->neighbor_name);
        return;
    }

    if (new_aspath) {
        if ((flags != UPF_OPTIONAL+UPF_TRANSIT) &&
            (flags != UPF_OPTIONAL+UPF_TRANSIT+UPF_PARTIAL)) {
            bgp_debug_ttyprintf(error_ttylist,
                                "UPDATE from %s contains incorrect flags for "
                                "NEW_ASPATH attribute",
                                nbr->neighbor_name);

            err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                            BGP_UPD_ERR_C4_ATTR_FLAGS_INVALID,
                                            flags, attr_code, len,
                                            errptr, 4);

            if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
                return;
            }
        }
    } else {
        if (flags != UPF_TRANSIT) {
            bgp_debug_ttyprintf(error_ttylist,
                                "UPDATE from %s contains incorrect flags for "
                                "ASPATH attribute",
                                nbr->neighbor_name);

            err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                            BGP_UPD_ERR_C4_ATTR_FLAGS_INVALID,
                                            flags, attr_code, len,
                                            errptr, 4);

            if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
                return;
            }
        }
    }

    rattr = BGP_PATH_TO_ATTR(rpath);
    if (rattr == NULL) {
        return;
    }

    if ((new_aspath && ((rattr->flags & BATTR_NEW_ASPATH) != 0)) ||
        (!new_aspath && ((rattr->flags & BATTR_ASPATH) != 0))) {
        bgp_debug_ttyprintf(error_ttylist,
                            "UPDATE from %s contains duplicate %sASPATH "
                            "attribute",
                            nbr->neighbor_name, (new_aspath ? "NEW_" : ""));

        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                    (new_aspath ?
                                      BGP_UPD_ERR_C4_ATTR_OPTR_DUPLICATE :
                                      BGP_UPD_ERR_C3_ATTR_NON_OPTR_DUPLICATE),
                                        flags, attr_code, len,
                                        errptr, 4);
        bgp_upd_err_store_reset_data(nbr,
                                     BGP_NONE,
                                     BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                     BNOT_UPDATE, BNOT_UPDATE_MALFORMED,
                                     errptr, errlen);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    if (len & 1) {
        bgp_debug_ttyprintf(error_ttylist,
                            "UPDATE from %s contains invalid %sASPATH len %u",
                            nbr->neighbor_name, (new_aspath ? "NEW_" : ""),
                            len);

        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                 (new_aspath ?
                                    BGP_UPD_ERR_C4_ATTR_NSPL_OPTR_LEN_INVALID :
                                    BGP_UPD_ERR_C2_ATTR_NON_OPTR_LEN_INVALID),
                                        flags, attr_code, len,
                                        errptr, 4);
        bgp_upd_err_store_reset_data(nbr,
                                     BGP_NONE,
                                     BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                     BNOT_UPDATE, BNOT_UPDATE_LENGTH,
                                     errptr, 4);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    /*
     * Step through the aspath and convert each AS number from
     * 2 bytes to 4 bytes.
     */
    aspath = data;
    aspathlen = len;
    if (!new_aspath && !nbr_4byte_as_cap) {
        for (pathptr = bgprtr_rcv_aspathbuf,
             convert_len = aspathlen; convert_len >= ASPATH_SEGMENT_OVERHEAD;
             convert_len -= ASPATH_SEGMENT_OVERHEAD) {
            switch (*aspath) {
            case AS_SET:
            case AS_SEQUENCE:
            case AS_CONFED_SEQUENCE:
            case AS_CONFED_SET:
                *pathptr++ = *aspath++;  /* aspath segment type */
                seg_cnt = *aspath++; /* number of segments  */
                *pathptr++ = seg_cnt;

                if (convert_len < (ASPATH_SEGMENT_OVERHEAD +
                                   (seg_cnt * ASPATHSIZE_OLD))) {
                    baspath.aslength = len;
                    baspath.aspath = data;
                    bgp_debug_ttyprintf(error_ttylist,
                                    "4-byte conversion invalid path segment "
                                    "in ASPATH received from %s",
                                    nbr->neighbor_name);
                    bgp4_aspath_data_invalid(nbr,
                                             msg, msg_len, errptr, errlen,
                                             flags, attr_code, len, rattr);
                    return;
                }

                convert_len -= (seg_cnt * ASPATHSIZE_OLD);

                while (seg_cnt > 0) {
                    *pathptr++ = 0;
                    *pathptr++ = 0;
                    *pathptr++ = *aspath++;
                    *pathptr++ = *aspath++;
                    seg_cnt--;
                    aspathlen += ASPATHSIZE_DELTA;
                }

                break;

            default:
                baspath.aslength = len;
                baspath.aspath = data;
                bgp_debug_ttyprintf(error_ttylist,
                                    "4-byte conversion invalid path segment "
                                    "in ASPATH received from %s",
                                    nbr->neighbor_name);
                bgp4_aspath_data_invalid(nbr,
                                         msg, msg_len, errptr, errlen,
                                         flags, attr_code, len, rattr);
                return;
            }
        }

        if (convert_len != 0) {
            baspath.aslength = len;
            baspath.aspath = data;
            bgp_debug_ttyprintf(error_ttylist,
                                "4-byte conversion invalid path segment "
                                "in ASPATH received from %s",
                                nbr->neighbor_name);
            bgp4_aspath_data_invalid(nbr,
                                     msg, msg_len, errptr, errlen,
                                     flags, attr_code, len, rattr);
            return;
        }

        aspath = bgprtr_rcv_aspathbuf;
    }

    /*
     * Reject the update if the AS-path is too long.
     */
    if (aspathlen > BGP_RCV_ASPATH_MAXLEN) {
        baspath.aslength = aspathlen;
        baspath.aspath = aspath;
        bgp_debug_ttyprintf(error_ttylist,
                            "AS Path received from %s is %u bytes which is "
                            "above the %u byte limit",
                            nbr->neighbor_name, aspathlen,
                            BGP_RCV_ASPATH_MAXLEN);

        *attr_wdr_flags |= BGP_UPD_WDR_ASPATH_TOO_LONG;

        goto abort_loop_check;
    }

    /*
     * Validate path segment
     */
    remove_confed_from_aspath = FALSE;

    if (!bgp_pathvalid(nbr, aspath, aspathlen, new_aspath, error_ttylist,
                       &remove_confed_from_aspath)) {
        baspath.aslength = aspathlen;
        baspath.aspath = aspath;
        bgp_debug_ttyprintf(error_ttylist,
                            "Invalid ASPATH segment received from %s",
                            nbr->neighbor_name);
        bgp4_aspath_data_invalid(nbr,
                                 msg, msg_len, errptr, errlen,
                                 flags, attr_code, len, rattr);
        return;
    }

    if (remove_confed_from_aspath) {
        bgp_debug_ttyprintf(error_ttylist,
                            "Removing the confed segments found in ASPATH"
                            " attribute from %s.",
                            nbr->neighbor_name);
        mod_aspathptr = new_aspath ?
                        bgprtr_cleanup_newaspathbuf : bgprtr_cleanup_aspathbuf;
        mod_aspathlen = bgp4_remove_confed_from_aspath(aspath, aspathlen,
                                                       mod_aspathptr);

        if (mod_aspathlen == 0) {
            bgp_debug_ttyprintf(error_ttylist,
                                "Ignoring NEW_ASPATH attribute from %s. After"
                                " removing confed segments from NEW_ASPATH"
                                "remaining NEW_ASPATH len is zero",
                                nbr->neighbor_name);
            return;
        }

        aspath = mod_aspathptr;
        aspathlen = mod_aspathlen;
    }

    if (!asloop_check) {
        goto abort_loop_check;
    }

    /*
     * Now we check for an AS routing loop for EBGP peer.
     * This has changed through the BGP4 drafts.  As of IETF
     * Houston, we now only are to check for -our- AS appearing
     * anywhere in the path.  If so, just ignore update.
     * Indicate that its malformed so that we invalidate the prefixes
     * advertised earlier.
     */
    if (nbr->cfg.is_internal && !vrf_ctx->cfg.as_ibgp_loopcheck) {
        goto abort_loop_check;
    }

    nbr_local_as = ((nbr->cfg.local_as_dual_as &&
                     nbr->local_as_dual_as_mode_native) ?
                    0 : nbr->cfg.local_as);

    if (bgp_asloop_detect(nbr, aspath, aspathlen, nbr_local_as,
                          myas_count, error_ttylist)) {
        *attr_wdr_flags |= BGP_UPD_WDR_ASPATH_LOOP;
    }

    if (new_aspath ||
        nbr->cfg.is_internal ||
        (nbr->nbrinfo.nbrinfo_flags & BNBRINFO_NBR_COMMONADMIN) ||
        (nbr->cfg.local_as == 0) ||
        nbr->cfg.local_as_no_prepend ||
        (nbr->cfg.local_as_dual_as &&
         nbr->local_as_dual_as_mode_native)) {

        goto abort_loop_check;
    }

    /* Stuff our local-as in the rcvd as-path */
    pathptr = bgprtr_merge_aspathbuf;

    if (*(aspath + 1) < UCHAR_MAX) {
        *pathptr++ = *aspath++;
        *pathptr++ = *aspath++ + 1;
        pathptr += bgp_write_asnum(TRUE, pathptr, nbr->cfg.local_as, NULL);
        memcpy(pathptr, aspath, aspathlen - ASPATH_SEGMENT_OVERHEAD);
        aspathlen += ASPATHSIZE;
    } else {
        *pathptr++ = AS_SEQUENCE;
        *pathptr++ = 1;
        pathptr += bgp_write_asnum(TRUE, pathptr, nbr->cfg.local_as, NULL);
        memcpy(pathptr, aspath, aspathlen);
        aspathlen += ASPATHSIZE + ASPATH_SEGMENT_OVERHEAD;
    }

    memcpy(bgprtr_rcv_aspathbuf, bgprtr_merge_aspathbuf, aspathlen);
    aspath = bgprtr_rcv_aspathbuf;

abort_loop_check:

    if (new_aspath) {
        rattr->flags |= BATTR_NEW_ASPATH;
        raspathptr = rattr->new_aspathptr;
    } else {
        rattr->flags |= BATTR_ASPATH;
        raspathptr = rattr->aspathptr;
    }

    raspathptr->aslength = aspathlen;
    raspathptr->aspath = aspath;

    return;
}


/*
 * bgp_validate_and_create_nexthop
 *
 */
static cerrno
bgp_validate_and_create_nexthop (bgp_nbrtype      *nbr,
                                 uint8_t          *msg,
                                 uint16_t          msg_len,
                                 uint8_t          *errptr,
                                 uint16_t          errlen,
                                 bgp_tblctxtype   *table_ctx,
                                 uchar_t           gw_afi,
                                 uchar_t           nlri_afi,
                                 bnexthoptype    **nexthop,
                                 uint8_t          *nhbuf,
                                 uint8_t           len,
                                 uint32_t         *attr_wdr_flags,
                                 bool              mp_nexthop,
                                 bgp_dbg_ttylist  *error_ttylist)
{
    cerrno                  rc = 0;
    bgp_upd_err_action_t    err_action = BGP_UPD_ERR_ACTION_NONE;
    bnexthop_validity_e     validity = BNEXTHOP_VALIDITY_UNKNOWN;
    bgp_gwctxtype          *gw_ctx = NULL;
    bnhtype                 nh;

    gw_ctx = table_ctx->vrf_ctx->gw_ctxblock[gw_afi];

    if (gw_ctx == NULL) {
        bgp_debug_ttyprintf(error_ttylist,
                            "Invalid nexthop gwafi=%u received from %s: "
                            "nexthop length %u, nlriafi=%u, tableafi=%u, "
                            "table=%s",
                            gw_afi, nbr->neighbor_name, len, nlri_afi,
                            table_ctx->afi, table_ctx->desc);

        if (mp_nexthop) {
            *attr_wdr_flags |= BGP_UPD_WDR_MP_NH_INVALID;
        } else {
            *attr_wdr_flags |= BGP_UPD_WDR_NH_INVALID;
        }

        return (BGP_ERROR_INCONSISTENT_ADDR);
    }

    rc = bgp_fill_rcvd_nh(gw_ctx, &nh, nlri_afi, nhbuf, len,
                          BNEXTHOP_ENABLE_MPLS(nbr, nlri_afi),
                          BNEXTHOP_VALIDATE_SYNC, &nbr->nbrinfo.nbr_addr,
                          !bgp_internal(&nbr->nbrinfo));

    if (CERR_IS_NOTOK(rc)) {
        bgp_debug_ttyprintf(error_ttylist,
                            "UPDATE from %s contains wrong nexthop "
                            "length of %u: gwafi=%u, nlriafi=%u, tableafi=%u, "
                            "table=%s, gwlen=%u, gwdaddrlen=%u",
                            nbr->neighbor_name, len,
                            gw_afi, nlri_afi, table_ctx->afi, table_ctx->desc,
                            gw_ctx->gwlen, gw_ctx->addrlen);
 

        return (rc);
    }

    BGP_DEBUG_UPD_IN(BGP_AF_NONE, BGP_NBR_TO_VRF_HANDLE(nbr), bgp_nbr_addr(nbr),
                     B_DIR_IN, NULL, 0,
                     BGP_OPT_NOFILTER, BGP_DBG_LEVEL_VERBOSE,
                     "UPDATE from %s contains nh %s, gw_afi %u, "
                     "flags 0x%x, nlri_afi %u",
                     nbr->neighbor_name, bgp_bnh2string(gw_ctx, &nh),
                     gw_afi, nh.flags, nh.nlri_afi);

    /*
     * Validate the value field of nexthop.
     */
    validity = BNEXTHOP_VALIDITY_UNKNOWN;

    switch (nlri_afi) {
    case BGP_AF_IPv4:
    case BGP_AF_IPv4_LABEL:
    case BGP_AF_IPv4_TUNNEL:
    case BGP_AF_IPv4_MDT:
    case BGP_AF_IPMCAST:
    case BGP_AF_VPNv4:
    case BGP_AF_L2VPN_VPLS:
    case BGP_AF_RT_CONSTRAINT:
    case BGP_AF_IPv4_MVPN:
    case BGP_AF_IPv6_MVPN:
        validity = bgp_validate_nexthop(gw_ctx, &nh, nbr, nexthop);
        break;

    case BGP_AF_IPv6:
    case BGP_AF_IPv6MCAST:
    case BGP_AF_VPNv6:
    case BGP_AF_IPv6_LABEL:
        validity = bgp_validate_mapped_ipv6_nexthop(gw_ctx, nlri_afi,
                                                    &nh, nbr, nexthop);
        break;

    default:
        bgp_debug_ttyprintf(error_ttylist,
                            "Invalid NLRI AFI during NH validation: "
                            "nbr=%s, nh=%s",
                            nbr->neighbor_name, bgp_bnh2string(gw_ctx, &nh));
        break;
    }

    /*
     * Convert validity to attr_wdr_flags. Invalid nexthops are
     * non-fatal -- the update msg is treated as a Withdraw.
     */
    switch (validity) {

    case BNEXTHOP_VALID:
         // Do nothing
        break;

    case BNEXTHOP_VALIDITY_UNKNOWN:
        bgp_debug_ttyprintf(error_ttylist,
                            "Unable to determine validity of nexthop (%s) "
                            "received from %s - discarding",
                            bgp_bnh2string(gw_ctx, &nh), nbr->neighbor_name);

        if (mp_nexthop) {
            *attr_wdr_flags |= BGP_UPD_WDR_MP_NH_MARTIAN;
        } else {
            *attr_wdr_flags |= BGP_UPD_WDR_NH_MARTIAN;
        }

        break;

    case BNEXTHOP_INVALID_MARTIAN:
        bgp_debug_ttyprintf(error_ttylist,
                            "Invalid nexthop (%s) received from %s",
                            bgp_bnh2string(gw_ctx, &nh), nbr->neighbor_name);

        if (mp_nexthop) {
            *attr_wdr_flags |= BGP_UPD_WDR_MP_NH_MARTIAN;
        } else {
            *attr_wdr_flags |= BGP_UPD_WDR_NH_MARTIAN;
        }

        break;

    case BNEXTHOP_INVALID_LOCAL:
        bgp_debug_ttyprintf(error_ttylist,
                            "Next hop received from %s is a "
                            "local address (%s)", nbr->neighbor_name,
                            bgp_bnh2string(gw_ctx, &nh));

        if (mp_nexthop) {
            *attr_wdr_flags |= BGP_UPD_WDR_MP_NH_LOCAL;
        } else {
            *attr_wdr_flags |= BGP_UPD_WDR_NH_LOCAL;
        }

        break;

    case BNEXTHOP_INVALID_NONCONNECTED:
        bgp_debug_ttyprintf(error_ttylist,
                            "UPDATE from %s has non-local next hop %s",
                            nbr->neighbor_name, bgp_bnh2string(gw_ctx, &nh));

        if (mp_nexthop) {
            *attr_wdr_flags |= BGP_UPD_WDR_MP_NH_NON_CONNECTED;
        } else {
            *attr_wdr_flags |= BGP_UPD_WDR_NH_NON_CONNECTED;
        }

        break;

    case BNEXTHOP_INVALID_LL_MARTIAN:
        bgp_debug_ttyprintf(error_ttylist,
                            "Invalid link-local nexthop (%s) received "
                            "from %s", bgp_bnh2string(gw_ctx, &nh),
                            nbr->neighbor_name);

        if (mp_nexthop) {
            *attr_wdr_flags |= BGP_UPD_WDR_MP_NH_MARTIAN;
        } else {
            *attr_wdr_flags |= BGP_UPD_WDR_NH_MARTIAN;
        }

        break;

    case BNEXTHOP_INVALID_LL_LOCAL:
        bgp_debug_ttyprintf(error_ttylist,
                            "Link-local nexthop received from %s "
                            "is our own address (%s)",
                            nbr->neighbor_name, bgp_bnh2string(gw_ctx, &nh));

        if (mp_nexthop) {
            *attr_wdr_flags |= BGP_UPD_WDR_MP_NH_LOCAL;
        } else {
            *attr_wdr_flags |= BGP_UPD_WDR_NH_LOCAL;
        }

        break;

    case BNEXTHOP_INVALID_SEMANTICS:
        bgp_debug_ttyprintf(error_ttylist,
                            "Nexthop %s received from %s has invalid semantics",
                            bgp_bnh2string(gw_ctx, &nh), nbr->neighbor_name);

        if (mp_nexthop) {
            *attr_wdr_flags |= BGP_UPD_WDR_MP_NH_SEMANTICS;
        } else {
            *attr_wdr_flags |= BGP_UPD_WDR_NH_SEMANTICS;
        }

        break;

    default:
        /*
         * Should only reach this point if a new validity type has been
         * added, but this switch statement hasn't been updated.
         */
        bgp_debug_ttyprintf(error_ttylist,
                            "Invalid NH Validity during NH validation: "
                            "nbr=%s, nh=%s, nhvalid=%d",
                            nbr->neighbor_name, bgp_bnh2string(gw_ctx, &nh),
                            validity);

        if (mp_nexthop) {
            *attr_wdr_flags |= BGP_UPD_WDR_MP_NH_INVALID;
        } else {
            *attr_wdr_flags |= BGP_UPD_WDR_NH_INVALID;
        }

        break;
    }

    BGP_DEBUG_UPD_IN(BGP_AF_NONE, BGP_NBR_TO_VRF_HANDLE(nbr),
                     bgp_nbr_addr(nbr), B_DIR_IN, NULL, 0,
                     BGP_OPT_NOFILTER, BGP_DBG_LEVEL_VERBOSE,
                     "NH-Validate-Create: addr=%s, len=%u, nlriafi=%u, nbr=%s, "
                     "gwafi=%u, gwlen=%u, gwaddrlen=%u::: "
                     "nhout=0x%08x, validity=%d, attrwdrflags=0x%08x",
                     bgp_bnh2string(gw_ctx, &nh), len, nlri_afi,
                     nbr->neighbor_name, gw_ctx->gw_afi, gw_ctx->gwlen,
                     gw_ctx->addrlen, (uint32_t)*nexthop, validity,
                     *attr_wdr_flags);

    return (rc);
}


/*
 * bgp4_rcv_nexthop -
 *
 * Parse BGP4 IPV4 nexthop attribute. Note that we should retain the IPV4
 * nexthop parsing as it is and it requires no special processing since
 * this attribute won't be present if BGP is carrying MP_REACH attribute.
 * This attribute should be ideally present for only ipv4 unicast updates.
 *
 * Return: uchar_t
 *   BNOT_UPDATE_FLAGS if the attribute flag doesn't say transient
 *   BNOT_UPDATE_MALFORMED if there is a duplicate nexthop attribute
 *   BNOT_UPDATE_LENGTH if the length of the attribute is not 4 bytes.
 *   BNOT_NONE if nexthop attribute is parsed correctly.
 *
 * Argument: nbr
 *   IN    - Neighbor associated with the update
 *
 * Argument: rpath
 *   IN    - Path structure
 *
 * Argument: data
 *   IN    - Update message data
 *
 * Argument: len
 *   IN    - Length of the attribute
 *
 * Argument: flags
 *   IN    - Attribute flags
 *
 * Argument: attr_wdr_flags
 *   INOUT - attribute errors
 *
 * Argument: bgp_dbg_ttylist *error_ttylist
 *   IN    - List of ttys for debug messages when errors are encountered.
 */
static void
bgp4_rcv_nexthop (bgp_nbrtype     *nbr,
                  uint8_t         *msg,
                  uint16_t         msg_len,
                  uint8_t         *errptr,
                  uint16_t         errlen,
                  uchar_t         *data,
                  ushort_t         len,
                  uchar_t          flags,
                  bpathtype       *rpath,
                  uint32_t        *attr_wdr_flags,
                  bgp_dbg_ttylist *error_ttylist)
{
    cerrno                  rc = 0;
    bgp_upd_err_action_t    err_action = BGP_UPD_ERR_ACTION_NONE;
    bgp_tblctxtype         *table_ctx = NULL;
    uint8_t                 gw_afi = BGP_AF_MAX;

    table_ctx = BGP_NBR_TO_TABLE_CTX(nbr, BGP_AF_IPv4);

    // Check if BGP_AF_IPv4 is configured and negotiated
    if ((!bgp4_rcv_afi_is_acceptable(nbr, BGP_TYPE_UPDATE,
                                    BGP_AF_IPv4,
                                    BGP_IPv4_ADDRESS_FAMILY, BGP_SAF_UNICAST,
                                    "NEXT_HOP attr", error_ttylist)) ||
        (table_ctx == NULL)) {

        bgp_debug_ttyprintf(error_ttylist,
                            "UPDATE from %s contains NEXT_HOP attribute for "
                            "IPv4-Unicast AF that is not configured "
                            "and/or negotiated",
                            nbr->neighbor_name);
        return;
    }

    if (flags != UPF_TRANSIT) {
        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                        BGP_UPD_ERR_C4_ATTR_FLAGS_INVALID,
                                        flags, ATT4_NEXTHOP, len,
                                        errptr, 3);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    if (rpath->bp_flags & BPATH_NEXTHOP) {
        bgp_debug_ttyprintf(error_ttylist,
                            "UPDATE from %s contains duplicate NEXT_HOP attr",
                            nbr->neighbor_name);

        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                        BGP_UPD_ERR_C3_ATTR_NON_OPTR_DUPLICATE,
                                        flags, ATT4_NEXTHOP, len,
                                        errptr, 3);
        bgp_upd_err_store_reset_data(nbr,
                                     BGP_NONE,
                                     BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                     BNOT_UPDATE, BNOT_UPDATE_MALFORMED,
                                     errptr, errlen);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    if (len != sizeof(in_addr_t)) {
        bgp_debug_ttyprintf(error_ttylist,
                            "UPDATE from %s contains NEXT_HOP attr with "
                            "invalid length %u",
                            nbr->neighbor_name, len);

        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                        BGP_UPD_ERR_C3_NH_LEN_INVALID,
                                        flags, ATT4_NEXTHOP, len,
                                        errptr, 3);
        bgp_upd_err_store_reset_data(nbr,
                                     BGP_NONE,
                                     BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                     BNOT_UPDATE, BNOT_UPDATE_LENGTH,
                                     errptr, errlen);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    /*
     * Get gateway AFI based on the received afi/safi. We assume that
     * when we reach here the afi/safi are verified and are valid
     */
    gw_afi = bgp_gw_afi_lookup(BGP_IPv4_ADDRESS_FAMILY, BGP_SAF_UNICAST);

    rc = bgp_validate_and_create_nexthop(nbr,
                                         msg, msg_len, errptr, errlen,
                                         table_ctx, gw_afi, BGP_AF_IPv4,
                                         &rpath->nexthop,
                                         data, sizeof(in_addr_t),
                                         attr_wdr_flags, FALSE,
                                         error_ttylist);
    if (CERR_IS_OK(rc)) {
        rpath->bp_flags |= BPATH_NEXTHOP;
    } else {
        rpath->nexthop = NULL;
    }

    return;
}


/*
 * bgp4_rcv_exitdisc -
 *
 * Parse BGP4 MED attribute.
 */
static void
bgp4_rcv_exitdisc (bgp_nbrtype     *nbr,
                   uint8_t         *msg,
                   uint16_t         msg_len,
                   uint8_t         *errptr,
                   uint16_t         errlen,
                   uchar_t         *data,
                   ushort_t         len,
                   uchar_t          flags,
                   bpathtype       *rpath,
                   bgp_dbg_ttylist *error_ttylist)
{
    bgp_upd_err_action_t    err_action = BGP_UPD_ERR_ACTION_NONE;
    battrtype              *rattr = NULL;

    if (flags != UPF_OPTIONAL) {
        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                        BGP_UPD_ERR_C4_ATTR_FLAGS_INVALID,
                                        flags, ATT4_EXITDISC, len,
                                        errptr, 3);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    rattr = BGP_PATH_TO_ATTR(rpath);
    if (rattr == NULL) {
        return;
    }

    if (rattr->flags & BATTR_METRIC) {
        bgp_debug_ttyprintf(error_ttylist,
                            "UPDATE from %s has duplicate MED attribute",
                            nbr->neighbor_name);

        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                        BGP_UPD_ERR_C3_ATTR_NON_OPTR_DUPLICATE,
                                        flags, ATT4_EXITDISC, len,
                                        errptr, 3);
        bgp_upd_err_store_reset_data(nbr,
                                     BGP_NONE,
                                     BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                     BNOT_UPDATE, BNOT_UPDATE_MALFORMED,
                                     errptr, errlen);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    if (len != 4) {
        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                      BGP_UPD_ERR_C2_ATTR_NON_OPTR_LEN_INVALID,
                                        flags, ATT4_EXITDISC, len,
                                        errptr, 3);
        bgp_upd_err_store_reset_data(nbr,
                                     BGP_NONE,
                                     BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                     BNOT_UPDATE, BNOT_UPDATE_LENGTH,
                                     errptr, 3);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    rattr->metric = GETLONG(data);
    rattr->flags |= BATTR_METRIC;

    return;
}


/*
 * bgp4_rcv_localpref -
 *
 * Parse BGP4 local preference attribute.
 */
static void
bgp4_rcv_localpref (bgp_nbrtype     *nbr,
                    uint8_t         *msg,
                    uint16_t         msg_len,
                    uint8_t         *errptr,
                    uint16_t         errlen,
                    uchar_t         *data,
                    ushort_t         len,
                    uchar_t          flags,
                    bpathtype       *rpath,
                    bgp_dbg_ttylist *error_ttylist)
{
    bgp_upd_err_action_t    err_action = BGP_UPD_ERR_ACTION_NONE;
    battrtype              *rattr = NULL;

    if (flags != UPF_TRANSIT) {
        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                        BGP_UPD_ERR_C4_ATTR_FLAGS_INVALID,
                                        flags, ATT4_LOCALPREF, len,
                                        errptr, 3);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    /*
     * Allowed to receive localpref from peer under common administration.
     */
    if (!bgp_commonadmin(&nbr->nbrinfo)) {
        BGP_DEBUG_UPD_IN(BGP_AF_NONE, BGP_NBR_TO_VRF_HANDLE(nbr),
                         bgp_nbr_addr(nbr), B_DIR_IN, NULL, 0, BGP_OPT_DFLT,
                         BGP_DBG_LEVEL_DETAIL,
                         "Ignoring local preference attribute (%s is not "
                         "under common administration)",
                         nbr->neighbor_name);
        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                        BGP_UPD_ERR_C4_ATTR_UNEXPECTED,
                                        flags, ATT4_LOCALPREF, len,
                                        errptr, 3);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    rattr = BGP_PATH_TO_ATTR(rpath);
    if (rattr == NULL) {
        return;
    }

    if (rattr->flags & BATTR_LOCALPREF) {
        bgp_debug_ttyprintf(error_ttylist,
                            "UPDATE from %s contains duplicate local "
                            "preference attribute",
                            nbr->neighbor_name);
        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                        BGP_UPD_ERR_C3_ATTR_NON_OPTR_DUPLICATE,
                                        flags, ATT4_LOCALPREF, len,
                                        errptr, 3);
        bgp_upd_err_store_reset_data(nbr,
                                     BGP_NONE,
                                     BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                     BNOT_UPDATE, BNOT_UPDATE_MALFORMED,
                                     errptr, errlen);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    if (len != 4) {
        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                      BGP_UPD_ERR_C2_ATTR_NON_OPTR_LEN_INVALID,
                                        flags, ATT4_LOCALPREF, len,
                                        errptr, 3);
        bgp_upd_err_store_reset_data(nbr,
                                     BGP_NONE,
                                     BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                     BNOT_UPDATE, BNOT_UPDATE_LENGTH,
                                     errptr, 3);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    rattr->localpref = GETLONG(data);
    rattr->flags |= BATTR_LOCALPREF;

    return;
}


/*
 * bgp4_rcv_atomicagg
 * Parse BGP4 atomic aggregate attribute.
 */
static void
bgp4_rcv_atomicagg (bgp_nbrtype     *nbr,
                    uint8_t         *msg,
                    uint16_t         msg_len,
                    uint8_t         *errptr,
                    uint16_t         errlen,
                    uchar_t         *data,
                    ushort_t         len,
                    uchar_t          flags,
                    bpathtype       *rpath,
                    bgp_dbg_ttylist *error_ttylist)
{
    bgp_upd_err_action_t    err_action = BGP_UPD_ERR_ACTION_NONE;
    battrtype              *rattr = NULL;

    /*
     * We treat this attribute as Optional-Transitive for the purpose
     * of error-handling.
     */

    if ((flags != UPF_TRANSIT) &&
        (flags != UPF_TRANSIT+UPF_OPTIONAL)) {
        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                        BGP_UPD_ERR_C4_ATTR_FLAGS_INVALID,
                                        flags, ATT4_ATOMICAGG, len,
                                        errptr, 3);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    rattr = BGP_PATH_TO_ATTR(rpath);
    if (rattr == NULL) {
        return;
    }

    if (rattr->flags & BATTR_ATOMICAGG) {
        bgp_debug_ttyprintf(error_ttylist,
                            "UPDATE from %s contains duplicate "
                            "ATOMIC_AGGREGATE attribute",
                            nbr->neighbor_name);
        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                        BGP_UPD_ERR_C3_ATTR_NON_OPTR_DUPLICATE,
                                        flags, ATT4_ATOMICAGG, len,
                                        errptr, 3);
        bgp_upd_err_store_reset_data(nbr,
                                     BGP_NONE,
                                     BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                     BNOT_UPDATE, BNOT_UPDATE_MALFORMED,
                                     errptr, errlen);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    if (len != 0) {
        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                     BGP_UPD_ERR_C2_ATTR_NON_OPTR_LEN_INVALID,
                                        flags, ATT4_ATOMICAGG, len,
                                        errptr, 3);
        bgp_upd_err_store_reset_data(nbr,
                                     BGP_NONE,
                                     BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                     BNOT_UPDATE, BNOT_UPDATE_LENGTH,
                                     errptr, 3);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    rattr->flags |= BATTR_ATOMICAGG;

    return;
}


/*
 * bgp4_rcv_aggregator -
 *
 * Parse BGP4 aggregator attribute.
 */
static void
bgp4_rcv_aggregator (bgp_nbrtype     *nbr,
                     uint8_t         *msg,
                     uint16_t         msg_len,
                     uint8_t         *errptr,
                     uint16_t         errlen,
                     uchar_t         *data,
                     ushort_t         len,
                     uchar_t          flags,
                     bpathtype       *rpath,
                     bool             new_aggregator,
                     bool            *honor_new_aspath,
                     bgp_dbg_ttylist *error_ttylist)
{
    bgp_upd_err_action_t    err_action = BGP_UPD_ERR_ACTION_NONE;
    battrtype              *rattr = NULL;
    uint8_t                 attr_code = 0;
    bool       nbr_4byte_as_cap; /* Peer advertised the 4-byte AS capability */
    bool       parse_4byte_as;   /* Aggregator AS number is 4-bytes          */
    uchar_t    required_len;     /* req length field for aggregator attr     */
    uint32_t   aggregator_as;    /* AS number from attribute                 */
    in_addr_t  aggregator_ip;    /* IP address from attribute                */
    bool       set_aggregator;   /* Set rattr's aggregator fields            */
    char       as_buf[ASCII_ASNUMSIZE]; /* AS buffer                         */

    if (new_aggregator) {
        attr_code = ATT4_NEW_AGGREGATOR;
    } else {
        attr_code = ATT4_AGGREGATOR;
    }

    if ((flags != UPF_OPTIONAL+UPF_TRANSIT) &&
        (flags != UPF_OPTIONAL+UPF_TRANSIT+UPF_PARTIAL)) {
        bgp_debug_ttyprintf(error_ttylist,
                            "UPDATE from %s contains incorrect flags for "
                            "%sAGGREGATOR attribute",
                            nbr->neighbor_name,
                            (new_aggregator ? "NEW_" : ""));

        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                        BGP_UPD_ERR_C4_ATTR_FLAGS_INVALID,
                                        flags, attr_code, len,
                                        errptr, 3);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    /*
     * An UPDATE should never contain multiple copies of an AGGREGATOR or
     * NEW_AGGREGATOR attribute.
     */
    rattr = BGP_PATH_TO_ATTR(rpath);
    if (rattr == NULL) {
        return;
    }

    if ((new_aggregator && ((rattr->flags & BATTR_NEW_AGGREGATOR) != 0)) ||
        (!new_aggregator && ((rattr->flags & BATTR_AGGREGATOR) != 0))) {
        bgp_debug_ttyprintf(error_ttylist,
                            "UPDATE from %s contains duplicate %sAGGREGATOR "
                            "attribute",
                            nbr->neighbor_name,
                            (new_aggregator ? "NEW_" : ""));

        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                        BGP_UPD_ERR_C4_ATTR_OPTR_DUPLICATE,
                                        flags, attr_code, len,
                                        errptr, 3);
        bgp_upd_err_store_reset_data(nbr,
                                     BGP_NONE,
                                     BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                     BNOT_UPDATE, BNOT_UPDATE_MALFORMED,
                                     errptr, errlen);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    /*
     * A peer that is capable of 4-byte AS should never send us a
     * NEW_AGGREGATOR attribute.
     */
    nbr_4byte_as_cap = (nbr->flags & BN_4BYTE_AS) != 0;

    if (nbr_4byte_as_cap && new_aggregator) {
        bgp_debug_ttyprintf(error_ttylist,
                            "Ignoring NEW_AGGREGATOR attribute from %s (a "
                            "4-byte AS capable peer)",
                            nbr->neighbor_name);
        return;
    }

    parse_4byte_as = nbr_4byte_as_cap || new_aggregator;

    if (parse_4byte_as) {
        required_len = 8;
    } else {
        required_len = 6;
    }

    if (len != required_len) {
        bgp_debug_ttyprintf(error_ttylist,
                            "UPDATE from %s contains invalid AGGREGATOR size "
                            "%u, expected %u",
                            nbr->neighbor_name, len, required_len);

        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                     BGP_UPD_ERR_C4_ATTR_NSPL_OPTR_LEN_INVALID,
                                        flags, attr_code, len,
                                        errptr, 3);
        bgp_upd_err_store_reset_data(nbr,
                                     BGP_NONE,
                                     BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                     BNOT_UPDATE, BNOT_UPDATE_LENGTH,
                                     errptr, 3);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    if (parse_4byte_as) {
        aggregator_as = GETLONG(data);
        aggregator_ip = GETADDR(data + ASPATHSIZE);
    } else {
        aggregator_as = GETSHORT(data);
        aggregator_ip = GETADDR(data + ASPATHSIZE_OLD);
    }

    /*
     * The NEW_AGGREGATOR and NEW_ASPATH attributes must be ignored if the
     * following are TRUE
     * - we receive AGGREGATOR and NEW_AGGREGATOR attributes
     * - the as value from the AGGREGATOR attribute is not AS_TRANS
     */
    set_aggregator = TRUE;

    if (new_aggregator) {
        if (rattr->flags & BATTR_AGGREGATOR) {
            if (rattr->aggregator_as != AS_TRANS) {
                *honor_new_aspath = FALSE;
                set_aggregator = FALSE;
                (void)bgp_util_asn_print(as_buf, sizeof(as_buf),
                                         0, rattr->aggregator_as);
                bgp_debug_ttyprintf(error_ttylist,
                                    "UPDATE from %s, aggregator AS is %s, "
                                    "ignoring NEW_AGGREGATOR and NEW_ASPATH",
                                    nbr->neighbor_name, as_buf);
            }
        }

        rattr->flags |= BATTR_NEW_AGGREGATOR;
    } else {
        if (rattr->flags & BATTR_NEW_AGGREGATOR) {
            if (aggregator_as != AS_TRANS) {
                *honor_new_aspath = FALSE;
                (void)bgp_util_asn_print(as_buf, sizeof(as_buf),
                                         0, aggregator_as);
                bgp_debug_ttyprintf(error_ttylist,
                                    "UPDATE from %s, aggregator AS is %s, "
                                    "ignoring NEW_AGGREGATOR and NEW_ASPATH",
                                    nbr->neighbor_name, as_buf);
            } else {
                /*
                 * AGGREGATOR contains AS_TRANS so do not overwrite the data
                 * from NEW_AGGREGATOR
                 */
                set_aggregator = FALSE;
            }
        }

        rattr->flags |= BATTR_AGGREGATOR;
    }

    if (set_aggregator) {
        rattr->aggregator_as = aggregator_as;
        rattr->aggregator_ip = aggregator_ip;
    }

    return;
}


/*
 * bgp_community_count
 * Given the size in bytes of an array of communities/extended communities,
 * return the number of elements in the array.
 */
static inline uint
bgp_community_count (bool extended,
                     int  len)
{
    if (extended) {
        return (EXTCOMM_COUNT(len));
    } else {
        return (COMMUNITY_COUNT(len));
    }
}


/*
 * bgp4_rcv_community -
 *
 * Parse BGP4 community attribute.
 */
static void
bgp4_rcv_community (bgp_nbrtype     *nbr,
                    uint8_t         *msg,
                    uint16_t         msg_len,
                    uint8_t         *errptr,
                    uint16_t         errlen,
                    uchar_t         *data,
                    ushort_t         len,
                    uchar_t          flags,
                    bpathtype       *rpath,
                    bool             extended,
                    bgp_dbg_ttylist *error_ttylist)
{
    bgp_upd_err_action_t    err_action = BGP_UPD_ERR_ACTION_NONE;
    battrtype              *rattr = NULL;
    uint8_t                 attr_code = 0;
    char                   *comm_str = NULL;
    uint32_t                comm_str_size = 0;
    uint32_t                battr_flags = 0;
    uint32_t    rcv_count;     /* Number of communities received             */
    uint32_t    max_community; /* Max number of communities to be accepted   */
    ushort_t   *comcount;      /* Number of communities received             */
    void       *community;     /* Generic pointer for community/extcommunity */
    bool        duplicate;     /* TRUE if duplicate community has been recvd */
    bool        ao;            /* TRUE if accept-own community present. */

    if (extended) {
        attr_code = ATT4_EXTCOMM;
    } else {
        attr_code = ATT4_COMMUNITY;
    }

    if ((flags != UPF_TRANSIT+UPF_OPTIONAL) &&
        (flags != UPF_TRANSIT+UPF_OPTIONAL+UPF_PARTIAL)) {
        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                        BGP_UPD_ERR_C4_ATTR_FLAGS_INVALID,
                                        flags, attr_code, len,
                                        errptr, 4);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    rattr = BGP_PATH_TO_ATTR(rpath);
    if (rattr == NULL) {
        return;
    }

    /*
     * Do type-dependent setup.
     */
    if (extended) {
        battr_flags = BATTR_EXTCOMM;
        max_community = BGP_EXTCOMM_MAX;
        /*sa_ignore NO_NULL_CHK*/
        comcount = &rattr->extcommptr->extcomcount;
        community = rattr->extcommptr->extcommunity;
    } else {
        battr_flags = BATTR_COMMUNITY;
        max_community = BGP_COMMUNITY_MAX;
        /*sa_ignore NO_NULL_CHK*/
        comcount = &rattr->commptr->comcount;
        community = rattr->commptr->community;
    }

    if (rattr->flags & battr_flags) {
        bgp_debug_ttyprintf(error_ttylist,
                            "UPDATE from %s contains duplicate COMMUNITY "
                            "path attribute",
                            nbr->neighbor_name);

        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                        BGP_UPD_ERR_C4_ATTR_OPTR_DUPLICATE,
                                        flags, attr_code, len,
                                        errptr, 4);
        bgp_upd_err_store_reset_data(nbr,
                                     BGP_NONE,
                                     BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                     BNOT_UPDATE, BNOT_UPDATE_MALFORMED,
                                     errptr, errlen);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    if ((extended && (len & 0x7)) || (len & 0x3)) {
        bgp_debug_ttyprintf(error_ttylist,
                            "UPDATE from %s contains %sCOMMUNITY attribute "
                            "with wrong length %u",
                            nbr->neighbor_name, (extended ? "EXT" : ""), len);

        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                      BGP_UPD_ERR_C2_ATTR_SPL_OPTR_LEN_INVALID,
                                        flags, attr_code, len,
                                        errptr, 4);
        bgp_upd_err_store_reset_data(nbr,
                                     BGP_NONE,
                                     BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                     BNOT_UPDATE, BNOT_UPDATE_LENGTH,
                                     errptr, 4);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    rcv_count = bgp_community_count(extended, len);

    if (rcv_count > max_community) {
        bgp_debug_ttyprintf(error_ttylist,
                            "UPDATE from %s contains %sCOMMUNITY attribute "
                            "with more %u communities whereas max is %u",
                            nbr->neighbor_name,
                            (extended ? "EXT" : ""), rcv_count, max_community);

        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                      BGP_UPD_ERR_C2_ATTR_SPL_OPTR_LEN_INVALID,
                                        flags, attr_code, len,
                                        errptr, 4);
        bgp_upd_err_store_reset_data(nbr,
                                     BGP_NONE,
                                     BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                     BNOT_UPDATE, BNOT_UPDATE_LENGTH,
                                     errptr, errlen);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    /*
     * Extract the community attributes and place it in
     * attrinfo structure. (ie bgp_router_com_buffer).
     */
    if (extended) {
        *comcount = bgp_extract_extcommunity(nbr, rattr, rpath, data, rcv_count,
                                             community, &battr_flags,
                                             &duplicate);
    } else {
        ao = FALSE;
        // TODO-pdh-ao: Pass attr_flags instead of ao bool ref.
        *comcount = bgp_extract_community(data, rcv_count, community,
                                          &duplicate, &ao);

        if (ao) {
            battr_flags |= BATTR_AO;
        }
    }

    if (duplicate) {
        comm_str_size = (len << 2) + 1;
        comm_str = bgp_calloc("Dupl-Comm", comm_str_size);
        if (comm_str != NULL) {
            bgp_debug_ttyprintf(error_ttylist,
                                "UPDATE from %s contains duplicate "
                                "%scommunities in %sCOMMUNITY attribute (%s)",
                                nbr->neighbor_name, (extended ? "ext" : ""),
                                (extended ? "EXT" : ""),
                                bgp_notification_data(data, len,
                                                      comm_str, comm_str_size));
            free(comm_str);
            comm_str = NULL;
        }
    }

    rattr->flags |= battr_flags;

    return;
}


/*
 * bgp4_rcv_clusterlist -
 *
 * Parse clusterlist attribute.
 */
static void
bgp4_rcv_clusterlist (bgp_nbrtype     *nbr,
                      uint8_t         *msg,
                      uint16_t         msg_len,
                      uint8_t         *errptr,
                      uint16_t         errlen,
                      uchar_t         *data,
                      ushort_t         len,
                      uchar_t          flags,
                      bpathtype       *rpath,
                      bool            *same_cluster,
                      uint32_t        *attr_wdr_flags,
                      bgp_dbg_ttylist *error_ttylist)
{
    bgp_upd_err_action_t    err_action = BGP_UPD_ERR_ACTION_NONE;
    brrinfotype    *rrinfo;
    uint32_t        cluster_id;
    int             ix, j;
    uchar_t        *cpi;

    if (flags != UPF_OPTIONAL) {
        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                        BGP_UPD_ERR_C4_ATTR_FLAGS_INVALID,
                                        flags, ATT4_CLUSTLIST, len,
                                        errptr, 4);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    if (!nbr->cfg.is_internal) {
        bgp_debug_ttyprintf(error_ttylist,
                           "UPDATE from external neighbor %s contains CLUSTER "
                           "LIST attribute",
                            nbr->neighbor_name);

        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                        BGP_UPD_ERR_C4_ATTR_UNEXPECTED,
                                        flags, ATT4_CLUSTLIST, len,
                                        errptr, 4);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    rrinfo = rpath->rrinfo;

    if (rrinfo->clusterlength != 0) {
        bgp_debug_ttyprintf(error_ttylist,
                            "UPDATE from %s contains duplicate CLUSTER LIST "
                            "attribute",
                            nbr->neighbor_name);

        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                        BGP_UPD_ERR_C3_ATTR_NON_OPTR_DUPLICATE,
                                        flags, ATT4_CLUSTLIST, len,
                                        errptr, 4);
        bgp_upd_err_store_reset_data(nbr,
                                     BGP_NONE,
                                     BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                     BNOT_UPDATE, BNOT_UPDATE_MALFORMED,
                                     errptr, errlen);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    if (((len & 3) != 0) || (len > BGP_RR_BUFLEN)) {
        bgp_debug_ttyprintf(error_ttylist,
                            "UPDATE from %s contains CLUSTER LIST attribute "
                            "with unsupported length %u (max %u)",
                            nbr->neighbor_name, len, BGP_RR_BUFLEN);

        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                      BGP_UPD_ERR_C2_ATTR_NON_OPTR_LEN_INVALID,
                                        flags, ATT4_CLUSTLIST, len,
                                        errptr, 4);
        bgp_upd_err_store_reset_data(nbr,
                                     BGP_NONE,
                                     BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                     BNOT_UPDATE, BNOT_UPDATE_LENGTH,
                                     errptr, 4);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    rrinfo->clusterlength = len;

    /*
     * Check for cluster loop. Look for a configured cluster-id
     * in the clusterlist. Indicate that the path is malformed
     * if there is a loop.
     *
     * If the first entry in the cluster-list is same as a
     * configured cluster-id, then the neighbor is configured to be
     * in the same cluster.
     */
    bgp_clusterdata_lock_rdlock();
    for (cpi = data, ix = len, j = 0; ix > 0; ix -= 4, cpi += 4) {
        cluster_id = GETLONG(cpi);

        if (bgp_cluster_id_lookup(cluster_id) != NULL) {
            if (j == 0) {
                *same_cluster = TRUE;
            } else {
                bgp_debug_ttyprintf(error_ttylist, "Detected route reflector "
                                    "cluster loop: received cluster-id %u "
                                    "from %s", cluster_id, nbr->neighbor_name);
                *attr_wdr_flags |= BGP_UPD_WDR_CLUSTER_LOOP;
                break;
            }
        }
        rrinfo->clusterlist[j++] = cluster_id;
    }
    bgp_clusterdata_lock_unlock();

    return;
}


/*
 * bgp4_rcv_originator -
 *
 * Parse BGP4 originator attribute.
 */
static void
bgp4_rcv_originator (bgp_nbrtype     *nbr,
                     uint8_t         *msg,
                     uint16_t         msg_len,
                     uint8_t         *errptr,
                     uint16_t         errlen,
                     uchar_t         *data,
                     ushort_t         len,
                     uchar_t          flags,
                     bpathtype       *rpath,
                     uint32_t        *attr_wdr_flags,
                     bgp_dbg_ttylist *error_ttylist)
{
    bgp_upd_err_action_t    err_action = BGP_UPD_ERR_ACTION_NONE;
    in_addr_t               originator = INADDR_ANY;
    bgp_vrfctxtype         *vrf_ctx = NULL;

    vrf_ctx = BGP_NBR_TO_VRF(nbr);

    if (flags != UPF_OPTIONAL) {
        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                        BGP_UPD_ERR_C4_ATTR_FLAGS_INVALID,
                                        flags, ATT4_ORIGINATOR, len,
                                        errptr, 3);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    if (!nbr->cfg.is_internal) {
        bgp_debug_ttyprintf(error_ttylist,
                            "UPDATE from external neighbor %s contains "
                            "ORIGINATOR attribute",
                            nbr->neighbor_name);

        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                        BGP_UPD_ERR_C4_ATTR_UNEXPECTED,
                                        flags, ATT4_ORIGINATOR, len,
                                        errptr, 3);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    if (rpath->rrinfo->originator != INADDR_ANY) {
        bgp_debug_ttyprintf(error_ttylist,
                            "UPDATE from %s contains duplicate ORIGINATOR "
                            "attribute",
                            nbr->neighbor_name);

        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                        BGP_UPD_ERR_C3_ATTR_NON_OPTR_DUPLICATE,
                                        flags, ATT4_ORIGINATOR, len,
                                        errptr, 3);
        bgp_upd_err_store_reset_data(nbr,
                                     BGP_NONE,
                                     BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                     BNOT_UPDATE, BNOT_UPDATE_MALFORMED,
                                     errptr, errlen);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    if (len != sizeof(in_addr_t)) {
        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                      BGP_UPD_ERR_C2_ATTR_NON_OPTR_LEN_INVALID,
                                        flags, ATT4_ORIGINATOR, len,
                                        errptr, 3);
        bgp_upd_err_store_reset_data(nbr,
                                     BGP_NONE,
                                     BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                     BNOT_UPDATE, BNOT_UPDATE_LENGTH,
                                     errptr, 3);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    originator = GETADDR(data);

    /*
     * If the originator is same as the local then it
     * indicates that a local client is connected to a RR in
     * some other cluster. Discard the update, its malformed.
     */
    if ((vrf_ctx != NULL) &&
        (originator == vrf_ctx->cfg.routerid)) {
        bgp_debug_ttyprintf(error_ttylist,
                            "UPDATE from %s discarded: local router is the "
                            "ORIGINATOR (%s)",
                            nbr->neighbor_name, bgp_ntoa_r(originator));
        *attr_wdr_flags |= BGP_UPD_WDR_ORIGINATOR_OWN;
    }

    /*
     * Use the ORIGINATOR attribute value as the router-id
     * for the received updates.
     */
    rpath->rrinfo->originator = originator;

    return;
}


/*
 * bgp4_rcv_ssa
 *
 * Parse BGP4 originator attribute.
 */
static void
bgp4_rcv_ssa (bgp_nbrtype     *nbr,
              uint8_t         *msg,
              uint16_t         msg_len,
              uint8_t         *errptr,
              uint16_t         errlen,
              uchar_t         *data,
              ushort_t         len,
              uchar_t          flags,
              bpathtype       *rpath,
              bgp_dbg_ttylist *error_ttylist)
{
    bgp_upd_err_action_t    err_action = BGP_UPD_ERR_ACTION_NONE;
    battrtype              *rattr = NULL;
    cerrno                  rc = 0;

    if ((flags != UPF_TRANSIT+UPF_OPTIONAL) &&
        (flags != UPF_TRANSIT+UPF_OPTIONAL+UPF_PARTIAL)) {
        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                        BGP_UPD_ERR_C4_ATTR_FLAGS_INVALID,
                                        flags, ATT4_SSA, len,
                                        errptr, 3);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    rattr = BGP_PATH_TO_ATTR(rpath);
    if (rattr == NULL) {
        return;
    }

    if ((rattr->flags & BATTR_SSA) != 0) {
        bgp_debug_ttyprintf(error_ttylist,
                            "UPDATE from %s contains duplicate SSA attribute",
                            nbr->neighbor_name);

        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                        BGP_UPD_ERR_C4_ATTR_OPTR_DUPLICATE,
                                        flags, ATT4_SSA, len,
                                        errptr, 3);
        bgp_upd_err_store_reset_data(nbr,
                                     BGP_NONE,
                                     BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                     BNOT_UPDATE, BNOT_UPDATE_MALFORMED,
                                     errptr, errlen);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    if (len > IPT_BGP_MAX_SSATLV_BUFSIZE) {
        bgp_debug_ttyprintf(error_ttylist,
                            "Invalid SSA attr len %u (max %u) received "
                            "from %s",
                             len, IPT_BGP_MAX_SSATLV_BUFSIZE,
                             nbr->neighbor_name);

        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                     BGP_UPD_ERR_C4_ATTR_NSPL_OPTR_LEN_INVALID,
                                        flags, ATT4_SSA, len,
                                        errptr, 4);
        bgp_upd_err_store_reset_data(nbr,
                                     BGP_NONE,
                                     BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                     BNOT_UPDATE, BNOT_UPDATE_LENGTH,
                                     errptr, 4);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    rc = ipt_bgp_process_peer_msg(data, len,
                                  &rattr->ssaptr->ssa_attr,
                                  (ipt_fwd_params *)&rattr->ssaptr->fwd_params);

    BGP_TRACE(BGP_TP_488,
              "from ", nbr->neighbor_name, rattr->ssaptr->fwd_params.ifhandle);

    if(rattr->ssaptr->fwd_params.ifhandle == 0x0){
        ios_msg_bgp_tun_null_ifhandle2("from ", nbr->neighbor_name);
    }

    if (CERR_IS_NOTOK(rc)) {
        bgp_debug_ttyprintf(error_ttylist,
                            "UPDATE from neighbor %s contains invalid SSA "
                            "attribute",
                            nbr->neighbor_name);

        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                        BGP_UPD_ERR_C4_ATTR_OPTR_DATA_INVALID,
                                        flags, ATT4_SSA, len,
                                        errptr, errlen);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    rattr->flags |= BATTR_SSA;

    return;
}


/*
 * bgp4_rcv_connector
 *
 * Parse BGP4 Connector attribute.
 */
static void
bgp4_rcv_connector (bgp_nbrtype     *nbr,
                    uint8_t         *msg,
                    uint16_t         msg_len,
                    uint8_t         *errptr,
                    uint16_t         errlen,
                    uchar_t         *data,
                    ushort_t         len,
                    uchar_t          flags,
                    bpathtype       *rpath,
                    bgp_dbg_ttylist *error_ttylist)
{
    bgp_upd_err_action_t    err_action = BGP_UPD_ERR_ACTION_NONE;
    battrtype              *rattr = NULL;
    bgp_conn_attrib *conn_attrib;
    uchar_t         *dataptr;
    ushort_t        count, i;

    if ((flags != UPF_TRANSIT+UPF_OPTIONAL) &&
        (flags != UPF_TRANSIT+UPF_OPTIONAL+UPF_PARTIAL)) {
        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                        BGP_UPD_ERR_C4_ATTR_FLAGS_INVALID,
                                        flags, ATT4_CONNECTOR, len,
                                        errptr, 3);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    rattr = BGP_PATH_TO_ATTR(rpath);
    if (rattr == NULL) {
        return;
    }

    if ((rattr->flags & BATTR_CONNECTOR) != 0) {
        bgp_debug_ttyprintf(error_ttylist,
                            "UPDATE from %s contains duplicate CONNECTOR attr",
                            nbr->neighbor_name);

        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                        BGP_UPD_ERR_C4_ATTR_OPTR_DUPLICATE,
                                        flags, ATT4_CONNECTOR, len,
                                        errptr, 3);
        bgp_upd_err_store_reset_data(nbr,
                                     BGP_NONE,
                                     BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                     BNOT_UPDATE, BNOT_UPDATE_MALFORMED,
                                     errptr, errlen);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    if (((len % BGP_CONNECTOR_FMT_LEN) != 0) ||
        (len > BGP_MAX_CONNTLV_BUFSIZE)) {
        bgp_debug_ttyprintf(error_ttylist,
                            "Invalid CONNECTOR attr len %u (max %u) received "
                            "from %s",
                             len, BGP_MAX_CONNTLV_BUFSIZE, nbr->neighbor_name);

        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                     BGP_UPD_ERR_C4_ATTR_NSPL_OPTR_LEN_INVALID,
                                        flags, ATT4_CONNECTOR, len,
                                        errptr, 3);
        bgp_upd_err_store_reset_data(nbr,
                                     BGP_NONE,
                                     BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                     BNOT_UPDATE, BNOT_UPDATE_LENGTH,
                                     errptr, 3);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    conn_attrib = &rattr->connptr->conn_attr;
    count = len / BGP_CONNECTOR_FMT_LEN;
    conn_attrib->conn_cnt = count;

    dataptr = data;
    for (i = 0; i < count; i++) {
        conn_attrib->conn_tlv[i].type = GETSHORT(dataptr);
        dataptr += sizeof(uint16_t);
        memcpy((uchar *)&(conn_attrib->conn_tlv[i].value[0]), dataptr,
               BGP_CONNECTOR_VALUE_LEN);
        dataptr += BGP_CONNECTOR_VALUE_LEN;
    }

    rattr->flags |= BATTR_CONNECTOR;

    return;
}

/*
 * bgp4_rcv_pmsi
 *
 * Parse BGP4 PMSI tunnel attribute.
 */
static void
bgp4_rcv_pmsi (bgp_nbrtype     *nbr,
               uint8_t         *msg,
               uint16_t         msg_len,
               uint8_t         *errptr,
               uint16_t         errlen,
               uchar_t         *data,
               ushort_t         len,
               uchar_t          flags,
               bpathtype       *rpath,
               bgp_dbg_ttylist *error_ttylist)
{
    bgp_upd_err_action_t    err_action = BGP_UPD_ERR_ACTION_NONE;
    battrtype              *rattr = NULL;
    bgp_pmsi_attrib *pmsi_attrib;
    uchar_t         *dataptr;

    if ((flags != UPF_TRANSIT+UPF_OPTIONAL) &&
        (flags != UPF_TRANSIT+UPF_OPTIONAL+UPF_PARTIAL)) {
        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                        BGP_UPD_ERR_C4_ATTR_FLAGS_INVALID,
                                        flags, ATT4_PMSI, len,
                                        errptr, 3);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    rattr = BGP_PATH_TO_ATTR(rpath);
    if (rattr == NULL) {
        return;
    }

    if ((rattr->flags & BATTR_PMSI) != 0) {
        bgp_debug_ttyprintf(error_ttylist,
                            "UPDATE from %s contains duplicate PMSI attr",
                            nbr->neighbor_name);

        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                        BGP_UPD_ERR_C4_ATTR_OPTR_DUPLICATE,
                                        flags, ATT4_PMSI, len,
                                        errptr, 3);
        bgp_upd_err_store_reset_data(nbr,
                                     BGP_NONE,
                                     BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                     BNOT_UPDATE, BNOT_UPDATE_MALFORMED,
                                     errptr, errlen);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    if ((len < PMSI_ATTRIB_FIXED_LEN) || (len > BGP_MAX_PMSITLV_BUFSIZE)) {
        bgp_debug_ttyprintf(error_ttylist,
                            "Invalid PMSI attr len %u (min %u, max %u) "
                            "received from %s",
                             len, PMSI_ATTRIB_FIXED_LEN,
                             BGP_MAX_PMSITLV_BUFSIZE, nbr->neighbor_name);

        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                     BGP_UPD_ERR_C4_ATTR_NSPL_OPTR_LEN_INVALID,
                                        flags, ATT4_PMSI, len,
                                        errptr, 3);
        bgp_upd_err_store_reset_data(nbr,
                                     BGP_NONE,
                                     BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                     BNOT_UPDATE, BNOT_UPDATE_LENGTH,
                                     errptr, 3);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    dataptr = data;
    pmsi_attrib = &rattr->pmsiptr->pmsi_attr;

    pmsi_attrib->flags = *dataptr;
    dataptr++;
    pmsi_attrib->type = *dataptr;
    dataptr++;
    pmsi_attrib->label = BGP_LABEL_FROM_NLRI(dataptr);
    dataptr += BGP_LABEL_BYTES;

   
    memcpy(&(pmsi_attrib->tun_id_value[0]), dataptr, 
           (len - PMSI_ATTRIB_FIXED_LEN));
    pmsi_attrib->pmsi_len = (len - PMSI_ATTRIB_FIXED_LEN);

    rattr->flags |= BATTR_PMSI;

    return;
}

/*
 * bgp4_rcv_ppmp
 *
 * Parse BGP4 PPMP label attribute.
 */
static void
bgp4_rcv_ppmp (bgp_nbrtype     *nbr,
               uint8_t         *msg,
               uint16_t         msg_len,
               uint8_t         *errptr,
               uint16_t         errlen,
               uchar_t         *data,
               ushort_t         len,
               uchar_t          flags,
               bpathtype       *rpath,
               bgp_dbg_ttylist *error_ttylist)
{
    bgp_upd_err_action_t    err_action = BGP_UPD_ERR_ACTION_NONE;
    battrtype              *rattr = NULL;
    bgp_ppmp_attrib *ppmp_attrib;
    uchar_t         *dataptr;

    if ((flags != UPF_TRANSIT+UPF_OPTIONAL) &&
        (flags != UPF_TRANSIT+UPF_OPTIONAL+UPF_PARTIAL)) {
        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                        BGP_UPD_ERR_C4_ATTR_FLAGS_INVALID,
                                        flags, ATT4_PPMP, len,
                                        errptr, 3);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    rattr = BGP_PATH_TO_ATTR(rpath);
    if (rattr == NULL) {
        return;
    }

    if ((rattr->flags & BATTR_PPMP) != 0) {
        bgp_debug_ttyprintf(error_ttylist,
                            "UPDATE from %s contains duplicate PPMP attr",
                            nbr->neighbor_name);

        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                        BGP_UPD_ERR_C4_ATTR_OPTR_DUPLICATE,
                                        flags, ATT4_PPMP, len,
                                        errptr, 3);
        bgp_upd_err_store_reset_data(nbr,
                                     BGP_NONE,
                                     BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                     BNOT_UPDATE, BNOT_UPDATE_MALFORMED,
                                     errptr, errlen);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    if (len != BGP_LABEL_BYTES) {
        bgp_debug_ttyprintf(error_ttylist,
                            "Invalid PPMP attr len %u (required %u) "
                            "received from %s",
                             len, BGP_LABEL_BYTES, nbr->neighbor_name);

        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                     BGP_UPD_ERR_C4_ATTR_NSPL_OPTR_LEN_INVALID,
                                        flags, ATT4_PPMP, len,
                                        errptr, 3);
        bgp_upd_err_store_reset_data(nbr,
                                     BGP_NONE,
                                     BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                     BNOT_UPDATE, BNOT_UPDATE_LENGTH,
                                     errptr, 3);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    dataptr = data;
    ppmp_attrib = &rattr->ppmpptr->ppmp_attr;

    ppmp_attrib->label = BGP_LABEL_FROM_NLRI(dataptr);
    dataptr += BGP_LABEL_BYTES;

    rattr->flags |= BATTR_PPMP;

    return;
}


/*
 * edt: * * bgp4_rcv_mp_reach
 *
 * Parse BGP4 Multiprotocol extension MP_REACH_NLRI attribute.
 *
 * Return: uchar_t
 *   BNOT_UPDATE_XXX in case of any error found while parsing
 *   BNOT_NONE if mp_reach attribute is parsed correctly.
 *
 * Argument: bgp_nbrtype *nbr
 *   IN    - Neighbor associated with the update
 *
 * Argument: bpathtype *rpath
 *   IN    - Path structure
 *
 * Argument: uchar_t *data
 *   IN    - Update message data
 *
 * Argument: ushort_t len
 *   IN    - Length of the attribute
 *
 * Argument: uchar_t flags
 *   IN    - Attribute flags
 *
 * Argument: uint32_t *attr_wdr_flags
 *   INOUT - Attribute errors
 *
 * Argument: bgp_dbg_ttylist *error_ttylist
 *   INOUT - List of ttys for debug messages when errors are encountered.
 */
static void
bgp4_rcv_mp_reach (bgp_nbrtype     *nbr,
                   uint8_t         *msg,
                   uint16_t         msg_len,
                   uint8_t         *errptr,
                   uint16_t         errlen,
                   uchar_t         *data,
                   ushort_t         len,
                   uchar_t          flags,
                   bpathtype       *rpath,
                   uint32_t        *attr_wdr_flags,
                   bgp_dbg_ttylist *error_ttylist)
{
    cerrno                  rc = 0;
    bgp_upd_err_action_t    err_action = BGP_UPD_ERR_ACTION_NONE;
    bgp_tblctxtype         *table_ctx = NULL;
    uint8_t                 nexthop_len = 0;
    uint16_t                rcvd_afi = 0;
    uint8_t                 rcvd_safi = 0;
    uint8_t                 afi = BGP_AF_NONE;
    uint8_t                *first = NULL;
    bnlritype              *bgp_nlri = NULL;
    bool                    ok = TRUE;
    uint8_t                 gw_afi = BGP_AF_NONE;

    first = data;

    /*
     * This attribute is optional.
     */
    if (flags != UPF_OPTIONAL) {
        bgp_debug_ttyprintf(error_ttylist,
                            "UPDATE for %s contains wrong flags 0x%x "
                            "for MP_REACH attribute",
                            nbr->neighbor_name, flags);

        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                        BGP_UPD_ERR_C4_ATTR_FLAGS_INVALID,
                                        flags, ATT4_MP_REACH_NLRI, len,
                                        errptr, 4);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            ok = FALSE;
        }
    }

    /*
     * Check for duplicates
     */
    if (ok) {
        if ((rpath->bp_flags & BPATH_MP_REACH) != 0) {
            bgp_debug_ttyprintf(error_ttylist,
                                "UPDATE from %s contains duplicate "
                                "MP_REACH attribute",
                                nbr->neighbor_name);

            err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                        BGP_UPD_ERR_C3_ATTR_NON_OPTR_DUPLICATE,
                                            flags, ATT4_MP_REACH_NLRI, len,
                                            errptr, 4);
            bgp_upd_err_store_reset_data(nbr,
                                         BGP_NONE,
                                         BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                         BNOT_UPDATE, BNOT_UPDATE_MALFORMED,
                                         errptr, errlen);

            if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
                ok = FALSE;
            }
        }
    }

    /*
     * Validate the length.
     */
    if (ok) {
        if (len < BGP_MPREACH_MINSIZE) {
            bgp_debug_ttyprintf(error_ttylist,
                                "UPDATE from %s has invalid MP_REACH length "
                                "%u (min %u)",
                                nbr->neighbor_name, len, BGP_MPREACH_MINSIZE);

            err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                      BGP_UPD_ERR_C2_ATTR_NON_OPTR_LEN_INVALID,
                                            flags, ATT4_MP_REACH_NLRI, len,
                                            errptr, 4);
            bgp_upd_err_store_reset_data(nbr,
                                         BGP_NONE,
                                         BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                         BNOT_UPDATE, BNOT_UPDATE_LENGTH,
                                         errptr, 4);

            if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
                ok = FALSE;
            }
        }
    }

    if (ok) {
        /*
         * First 3 bytes are AFI and SAFI
         */
        rcvd_afi = GETSHORT(data);
        data += sizeof(uint16_t);
        rcvd_safi = *data++;

        afi = bgp_get_internal_afi(rcvd_afi, rcvd_safi);

        if (afi < BGP_AF_MAX) {
            table_ctx = BGP_NBR_TO_TABLE_CTX(nbr, afi);
        }

        // Check if this AFI is configured and negotiated
        if ((!bgp4_rcv_afi_is_acceptable(nbr, BGP_TYPE_UPDATE,
                                         afi, rcvd_afi, rcvd_safi,
                                         "MP_REACH attr", error_ttylist)) ||
            (table_ctx == NULL)) {

            bgp_debug_ttyprintf(error_ttylist,
                                "UPDATE from %s contains MP_REACH attribute "
                                "for unsupported afi/safi: %u/%u",
                                nbr->neighbor_name, rcvd_afi, rcvd_safi);
            ok = FALSE;
        }
    }

    if (ok) {
        bgp_nlri = bnlri_alloc();

        if (bgp_nlri == NULL) {
            err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                            BGP_UPD_ERR_C1_MEM_ALLOC_FAIL,
                                            flags, ATT4_MP_REACH_NLRI, len,
                                            NULL, 0);
            bgp_upd_err_store_reset_data(nbr,
                                         BGP_NOMEMORY,
                                         BGP_POSTIT_TYPE_NOMEMORY,
                                         0, 0, NULL, 0);
            ios_msg_bgp_nomem_reset("MP_REACH NLRI");

            ok = FALSE;
        }
    }

    if (ok) {
        nexthop_len = *data++;

        if (len < (nexthop_len + BGP_MPREACH_MINSIZE)) {
            bgp_debug_ttyprintf(error_ttylist,
                                "UPDATE from %s has inconsistent MP_REACH "
                                "nexthop length %u (attr len %u)",
                                nbr->neighbor_name, nexthop_len, len);

            err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                     BGP_UPD_ERR_C2_ATTR_NON_OPTR_DATA_INVALID,
                                        flags, ATT4_MP_REACH_NLRI, len,
                                        errptr, errlen);
            bgp_upd_err_store_reset_data(nbr,
                                         BGP_NONE,
                                         BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                         BNOT_UPDATE, BNOT_UPDATE_ORIGIN,
                                         errptr, errlen);

            ok = FALSE;
        }
    }

    if (ok) {
        bgp_nlri->code = BGP_REACHABLE_NLRI;
        bgp_nlri->flags |= BNLRI_MP;

        // NOTE: Currently we don't check/allow explicitly for nexthop length 0
        //       condition. It is handled as part of regular nexthop
        //       length validation below.

        gw_afi = bgp_gw_afi_lookup_with_type(rcvd_afi, rcvd_safi,
                                             nbr->cfg.is_internal,
                                             data, nexthop_len);

        /*
         * Perform martian check, also see if the nexthop advertised is
         * not our own address as well as if the neighbor is directly
         * connected eBGP peer it has advertized us a directly connected
         * nexthop.
         */
        rc = bgp_validate_and_create_nexthop(nbr,
                                             msg, msg_len, errptr, errlen,
                                             table_ctx, gw_afi, afi,
                                             &bgp_nlri->nexthop,
                                             data, nexthop_len,
                                             attr_wdr_flags, TRUE,
                                             error_ttylist);

        if (CERR_IS_NOTOK(rc)) {
            bgp_nlri->nexthop = NULL;
        }

        data += nexthop_len;
    }

    if (ok) {
        /*
         * The SNPA length field defined in RFC 2858 is changed to "reserved"
         * in RFC 4760.  Just skip the reserved field.
         */
        data++;
    }

    /*
     * Store and enqueue the NLRI block
     */
    if (ok) {
        // NOTE: Record the fact that MP_REACH was received for this path
        //       even if the NLRI block length is 0.
        rpath->bp_flags |= BPATH_MP_REACH;

        bgp_nlri->afi = afi;
        bgp_nlri->rcvd_afi = rcvd_afi;
        bgp_nlri->rcvd_safi = rcvd_safi;
        bgp_nlri->nlri = data;
        bgp_nlri->len = len - (data - first);
    }

    if ((ok) && (bgp_nlri->len != 0)) {
        queue_enqueue(&bgpinfo_nlriQ, bgp_nlri);
    } else {
        if (bgp_nlri != NULL) {
            if (bgp_nlri->nexthop != NULL) {
                bgp_nexthop_unlock(bgp_nlri->nexthop, NULL);
                bgp_nlri->nexthop = NULL;
            }

            bnlri_free(bgp_nlri);
            bgp_nlri = NULL;
        }
    }

    return;
}


/*
 * edt: * * bgp4_rcv_mp_unreach
 *
 * Parse BGP4 Multiprotocol extension MP_UNREACH_NLRI attribute.
 *
 * Return: uchar_t
 *   BNOT_UPDATE_XXX in case of any error found while parsing
 *   BNOT_NONE if mp_unreach attribute is parsed correctly.
 *
 * Argument: bgp_nbrtype *nbr
 *   IN    - Neighbor associated with the update
 *
 * Argument: bpathtype *rpath
 *   IN    - Path structure
 *
 * Argument: uchar_t *data
 *   IN    - Update message data
 *
 * Argument: ushort_t len
 *   IN    - Length of the attribute
 *
 * Argument: uchar_t flags
 *   IN    - Attribute flags
 *
 * Argument: ushort_t upd_len
 *   IN    - Size of the update message
 *
 * Argument: bgp_dbg_ttylist *error_ttylist
 *   INOUT - List of ttys for debug messages when errors are encountered.
 */
static void
bgp4_rcv_mp_unreach (bgp_nbrtype     *nbr,
                     uint8_t         *msg,
                     uint16_t         msg_len,
                     uint8_t         *errptr,
                     uint16_t         errlen,
                     uchar_t         *data,
                     ushort_t         len,
                     uchar_t          flags,
                     bpathtype       *rpath,
                     bmsgtype        *bmsg,
                     uint16_t         upd_len,
                     bgp_dbg_ttylist *error_ttylist)
{
    bgp_upd_err_action_t    err_action = BGP_UPD_ERR_ACTION_NONE;
    uint16_t                rcvd_afi = 0;
    uint8_t                 rcvd_safi = 0;
    uint8_t                 afi = BGP_AF_NONE;
    bnlritype              *bgp_nlri = NULL;
    bgp_tblctxtype         *table_ctx = NULL;
    bool                    ok = TRUE;


    if (bmsg == NULL) {
        bgp_debug_ttyprintf(error_ttylist,
                            "NULL bmsg encountered when processing "
                            "MP_UNREACH attribute from %s",
                            nbr->neighbor_name);
        return;
    }

    /*
     * This attribute is optional.
     */
    if (flags != UPF_OPTIONAL) {
        bgp_debug_ttyprintf(error_ttylist,
                            "UPDATE for %s contains wrong flags 0x%x "
                            "for MP_UNREACH attribute",
                            nbr->neighbor_name, flags);

        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                        BGP_UPD_ERR_C4_ATTR_FLAGS_INVALID,
                                        flags, ATT4_MP_UNREACH_NLRI, len,
                                        errptr, 4);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            ok = FALSE;
        }
    }

    /*
     * Check for duplicate attribute
     */
    if (ok) {
        if ((bmsg->bmsg_flags & BMSG_MP_UNREACH) != 0) {
            bgp_debug_ttyprintf(error_ttylist,
                                "UPDATE for %s contains duplicate "
                                "MP_UNREACH attr",
                                nbr->neighbor_name);

            err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                        BGP_UPD_ERR_C3_ATTR_NON_OPTR_DUPLICATE,
                                            flags, ATT4_MP_UNREACH_NLRI, len,
                                            errptr, 4);
            bgp_upd_err_store_reset_data(nbr,
                                         BGP_NONE,
                                         BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                         BNOT_UPDATE, BNOT_UPDATE_MALFORMED,
                                         errptr, errlen);

            if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
                ok = FALSE;
            }
        }
    }

    if (ok) {
        if (len < BGP_MPUNREACH_MINSIZE) {
            bgp_debug_ttyprintf(error_ttylist,
                                "UPDATE from %s has invalid MP_UNREACH length "
                                "%u (min %u)",
                                nbr->neighbor_name, len, BGP_MPUNREACH_MINSIZE);

            err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                      BGP_UPD_ERR_C2_ATTR_NON_OPTR_LEN_INVALID,
                                            flags, ATT4_MP_UNREACH_NLRI, len,
                                            errptr, 4);
            bgp_upd_err_store_reset_data(nbr,
                                         BGP_NONE,
                                         BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                         BNOT_UPDATE, BNOT_UPDATE_LENGTH,
                                         errptr, 4);

            if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
                ok = FALSE;
            }
        }
    }

    if (ok) {
        rcvd_afi = GETSHORT(data);
        data += sizeof(uint16_t);
        rcvd_safi = *data++;

        afi = bgp_get_internal_afi(rcvd_afi, rcvd_safi);

        if (afi < BGP_AF_MAX) {
            table_ctx = BGP_NBR_TO_TABLE_CTX(nbr, afi);
        }

        // Check if this AFI is configured and negotiated
        if ((!bgp4_rcv_afi_is_acceptable(nbr, BGP_TYPE_UPDATE,
                                         afi, rcvd_afi, rcvd_safi,
                                         "MP_UNREACH attr", error_ttylist)) ||
            (table_ctx == NULL)) {

            bgp_debug_ttyprintf(error_ttylist,
                                "UPDATE from %s contains MP_UNREACH attribute "
                                "for unsupported afi/safi: %u/%u",
                                nbr->neighbor_name, rcvd_afi, rcvd_safi);
            ok = FALSE;
        }
    }

    if (ok) {
        /*
         * Check if this is an MP EOR message. MP EOR is an update message
         * with only MP-UNREACH attribute without any withdrawn prefixes.
         * So excluding header the update message size will be
         * BGP_MP_EOR_DATASIZE or BGP_MP_EOR_EXT_DATASIZE and MP_UNREACH
         * attribute size will be BGP_MPUNREACH_MINSIZE. For the case
         * of BGP_MP_EOR_EXT_DATASIZE, a check for UPF_EXTENDED is
         * applicable, however the flags have been reset at this point.
         * If it is a EOR, send an async message to see if we can come out of
         * the read-only mode.
         */
        if (((nbr->cfg.gr_enabled) ||
             (afi == BGP_AF_RT_CONSTRAINT)) &&
            ((upd_len == BGP_MP_EOR_DATASIZE) ||
             (upd_len == BGP_MP_EOR_EXT_DATASIZE)) &&
            (len == BGP_MPUNREACH_MINSIZE)) {

            bgp_process_eor(nbr, afi, TRUE);

            if (afi == BGP_AF_RT_CONSTRAINT) {
                BGP_TRACE(BGP_TP_778, nbr->neighbor_name);
                BGP_DEBUG_UPD_IN(afi, BGP_TABLE_CTX_TO_VRF_HANDLE(table_ctx),
                        bgp_nbr_addr(nbr), B_DIR_IN, NULL, 0,
                        BGP_OPT_DFLT, BGP_DBG_LEVEL_SUMMARY,
                        "Explicit MP EoR received from %s, triggering"
                        "VPN update gen",
                        nbr->neighbor_name);
            }

            ok = FALSE;
        }
    }

    if (ok) {
        /*
         * We removed AFI/SAFI from the attribute. We didn't adjust
         * the length at that point for EoR check above. So adjust the length
         * by 3 bytes now(2 bytes for AFI and 1 byte for SAFI).
         */
        len -= BGP_MPUNREACH_MINSIZE;

        bgp_nlri = bnlri_alloc();

        if (bgp_nlri == NULL) {
            err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                            BGP_UPD_ERR_C1_MEM_ALLOC_FAIL,
                                            flags, ATT4_MP_UNREACH_NLRI, len,
                                            NULL, 0);
            bgp_upd_err_store_reset_data(nbr,
                                         BGP_NOMEMORY,
                                         BGP_POSTIT_TYPE_NOMEMORY,
                                         0, 0, NULL, 0);
            ios_msg_bgp_nomem_reset("MP_UNREACH NLRI");

            ok = FALSE;
        }
    }

    if (ok) {
        // NOTE: Record the fact that MP_UNREACH was received on this msg
        //       even if the NLRI block length is 0.
        bmsg->bmsg_flags |= BMSG_MP_UNREACH;

        bgp_nlri->code = BGP_UNREACHABLE_NLRI;
        bgp_nlri->flags |= BNLRI_MP;

        bgp_nlri->afi = afi;
        bgp_nlri->rcvd_afi = rcvd_afi;
        bgp_nlri->rcvd_safi = rcvd_safi;
        bgp_nlri->nlri = data;
        bgp_nlri->len = len;
    }

    if ((ok) && (bgp_nlri->len != 0)) {
        queue_enqueue(&bgpinfo_nlriQ, bgp_nlri);
    } else {
        if (bgp_nlri != NULL) {
            bnlri_free(bgp_nlri);
            bgp_nlri = NULL;
        }
    }

    return;
}


/*
 * bgp4_rcv_unknown -
 *
 * Parse unknown attribute.
 */
static void
bgp4_rcv_unknown (bgp_nbrtype     *nbr,
                  uint8_t         *msg,
                  uint16_t         msg_len,
                  uint8_t         *errptr,
                  uint16_t         errlen,
                  uint8_t          attr_flags,
                  uint8_t          attr_code,
                  uint16_t         attr_len,
                  bpathtype       *rpath,
                  bgp_dbg_ttylist *error_ttylist)
{
    bgp_upd_err_action_t    err_action = BGP_UPD_ERR_ACTION_NONE;
    battrtype              *rattr = NULL;
    uint8_t                *cpi = NULL;

    rattr = BGP_PATH_TO_ATTR(rpath);
    if (rattr == NULL) {
        return;
    }

    if ((attr_flags & UPF_OPTIONAL) == 0) {
        bgp_debug_ttyprintf(error_ttylist,
                            "UPDATE from %s contains unrecognized "
                            "mandatory attribute %u",
                            nbr->neighbor_name, attr_code);

        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                        BGP_UPD_ERR_C2_ATTR_MAND_UNRECOG,
                                        attr_flags, attr_code, attr_len,
                                        errptr, 3);
        bgp_upd_err_store_reset_data(nbr,
                                     BGP_NONE,
                                     BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                     BNOT_UPDATE, BNOT_UPDATE_UNRECOG,
                                     errptr, 3);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }

        // Set the Optional flag on the attribute (i.e. do local repair)
        *errptr |= UPF_OPTIONAL;
    }

    /*
     * Quietly ignore unrecognized, non-transit attributes
     */
    if ((attr_flags & UPF_TRANSIT) == 0) {
        bgp_debug_ttyprintf(error_ttylist,
                            "UPDATE from %s contains unrecognized "
                            "non-transitive attribute %u",
                            nbr->neighbor_name, attr_code);
        return;
    }

    /*
     * Do not pass an unrecognized, duplicate, optional transitive attribute.
     * A duplicate attribute would be cause for either session reset or for
     * treating an update message as withdraw when the attribute is finally
     * recognized somewhere, either by a direct neighbor or a remote one.
     *
     * Strictly speaking, the neighbor is at fault for passing a duplicate
     * attribute (even when the partial bit is set), and we could either
     * reset the session or treat the update as withdraw.  But we can not
     * -- as the neighbor could be an IOS/XR router and historically there
     * was no such duplicate check before Sept 2009.
     *
     * In order to avoid a session reset by some other direct neighbors,
     * we suppress the duplicate and let the first instance go through.
     * That is the best we can do.
     */
    if (bgprtr_rcv_attrs[attr_code]) {
        bgp_debug_ttyprintf(error_ttylist,
                            "UPDATE from %s contains unrecognized, duplicate "
                            "attribute %u",
                            nbr->neighbor_name, attr_code);
        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                        BGP_UPD_ERR_C4_ATTR_UNRECOG_DUPLICATE,
                                        attr_flags, attr_code, attr_len,
                                        errptr, 4);
        bgp_upd_err_store_reset_data(nbr,
                                     BGP_NONE,
                                     BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                     BNOT_UPDATE, BNOT_UPDATE_MALFORMED,
                                     errptr, errlen);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    bgprtr_rcv_attrs[attr_code] = TRUE;

    /*
     * Record and pass along unrecognized transit attributes.
     * Set partial bit to indicate we didn't update attribute.
     */
    *errptr |= UPF_PARTIAL;

    if ((rattr->transptr == NULL) || (rattr->translen == 0)) {
        rattr->transptr = bgp_calloc("Unk-attr", errlen);

        if (rattr->transptr == NULL) {
            rattr->translen = 0;
            return;
        }

        rattr->translen = errlen;
        bcopy(errptr, rattr->transptr, errlen);
    } else {
        cpi = rattr->transptr;

        rattr->transptr = bgp_calloc("Unk-attr-multi",
                                    (errlen + rattr->translen));

        if (rattr->transptr == NULL) {
            rattr->transptr = cpi;
            return;
        }

        bcopy(cpi, rattr->transptr, rattr->translen);
        bcopy(errptr, (rattr->transptr + rattr->translen), errlen);
        rattr->translen += errlen;

        free(cpi);
        cpi = NULL;
    }

    return;
}


/*
 * bgp4_rcv_aigp
 *
 * Parse received AIGP attribute.
 */
static void
bgp4_rcv_aigp (bgp_nbrtype     *nbr,
               uint8_t         *msg,
               uint16_t         msg_len,
               uint8_t         *errptr,
               uint16_t         errlen,
               uchar_t         *data,
               ushort_t         len,
               uchar_t          flags,
               bpathtype       *rpath,
               bgp_dbg_ttylist *error_ttylist)
{
    bgp_upd_err_action_t    err_action = BGP_UPD_ERR_ACTION_NONE;
    battrtype              *rattr = NULL;
    uchar_t         type;
    ushort_t        tlv_len;

    if (flags != UPF_OPTIONAL) {
        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                        BGP_UPD_ERR_C4_ATTR_FLAGS_INVALID,
                                        flags, ATT4_AIGP, len,
                                        errptr, 3);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    rattr = BGP_PATH_TO_ATTR(rpath);
    if (rattr == NULL) {
        return;
    }

    if (rattr->flags & BATTR_AIGP) {
        bgp_debug_ttyprintf(error_ttylist,
                            "UPDATE from %s has duplicate AIGP attribute",
                            nbr->neighbor_name);

        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                        BGP_UPD_ERR_C3_ATTR_NON_OPTR_DUPLICATE,
                                        flags, ATT4_AIGP, len,
                                        errptr, 3);
        bgp_upd_err_store_reset_data(nbr,
                                     BGP_NONE,
                                     BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                     BNOT_UPDATE, BNOT_UPDATE_MALFORMED,
                                     errptr, errlen);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    //EHTODO Loop thru all the TLVs in the attribute...

    // Check for Type+Length (3 bytes) fields
    //EHTODO Change hardcoded values...
    if (len < 3) {
        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                      BGP_UPD_ERR_C2_ATTR_NON_OPTR_LEN_INVALID,
                                        flags, ATT4_AIGP, len,
                                        errptr, 3);
        bgp_upd_err_store_reset_data(nbr,
                                     BGP_NONE,
                                     BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                     BNOT_UPDATE, BNOT_UPDATE_LENGTH,
                                     errptr, 3);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    type = *data++;
    tlv_len = GETSHORT(data);
    data += sizeof(ushort_t);

    if (type != BGP_AIGP_ATTR_TYPE_1) {
         bgp_debug_ttyprintf(error_ttylist,
                             "UPDATE from %s has AIGP TLV of type %u",
                            nbr->neighbor_name, type);
         // Just silently ignore this attribute; we support only Type-1
         //EHTODO Confirm this !!
         return;
    }

    if ((len != BGP_AIGP_ATTR_TYPE_1_LENGTH) ||
        (tlv_len != BGP_AIGP_ATTR_TYPE_1_LENGTH)) {
        bgp_debug_ttyprintf(error_ttylist,
                            "UPDATE from %s has invalid AIGP length: "
                            "attr len %u, Type-1 TLV length %u",
                            nbr->neighbor_name, len, tlv_len);

        err_action = bgp_upd_err_handle(nbr, msg, msg_len,
                                      BGP_UPD_ERR_C2_ATTR_NON_OPTR_LEN_INVALID,
                                        flags, ATT4_AIGP, len,
                                        errptr, errlen);
        bgp_upd_err_store_reset_data(nbr,
                                     BGP_NONE,
                                     BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                     BNOT_UPDATE, BNOT_UPDATE_LENGTH,
                                     errptr, errlen);

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            return;
        }
    }

    rattr->aigp = (((uint64_t)GETLONG(data)) << 32) | (uint64_t)GETLONG(data+4);
    data += sizeof(uint64_t);

    rattr->flags |= BATTR_AIGP;

    return;
}


/*
 * bgp4_rcv_attributes
 *
 * EDT in bgp_util.h.
 */
void
bgp4_rcv_attributes (bgp_nbrtype      *bgp,
                     uint8_t          *msg,
                     uint16_t          msg_len,
                     uint16_t          upd_len,
                     uint8_t          *attr_block_data,
                     uint16_t          attr_block_len,
                     uint16_t          ipv4_reach_len,
                     bmsgtype         *bmsg,
                     bpathtype        *msgin_pathptr,
                     bool             *same_cluster,
                     uchar_t          *myas_count,
                     bool              asloop_check,
                     uint32_t         *attr_wdr_flags,
                     bgp_dbg_ttylist  *error_ttylist)
{
    uint8_t                 filter_action = BGP_UPD_FILTER_ACTION_NONE;
    bgp_upd_err_action_t    err_action = BGP_UPD_ERR_ACTION_NONE;
    uint8_t                *rcv_data = NULL;
    uint16_t                rcv_len = 0;
    uint8_t                *errptr = NULL;
    uint16_t                errlen = 0;
    uint8_t                 attr_flags = 0;
    uint8_t                 attr_code = 0;
    uint16_t                attr_len = 0;
    uint8_t                *attr_data = NULL;
    battrtype              *attr = NULL;
    bool                    honor_new_aspath = TRUE;
    int                     unknown_attr_cnt = 0;

    *same_cluster = FALSE;

    //bgp_debug_ttyprintf(error_ttylist,
                    //"--%s--: START: nbr=%s:: msg=0x%08x/%u, updlen=%u, "
                    //"attrbl=0x%08x/%u, ipv4reachlen=%u, msginpath=0x%08x, "
                    //"asloopcheck=%d, attrwdrfl=0x%08x",
                    //__FUNCTION__,
                    //bgp->neighbor_name,
                    //(uint32_t)msg, msg_len, upd_len,
                    //(uint32_t)attr_block_data, attr_block_len,
                    //ipv4_reach_len, (uint32_t)msgin_pathptr,
                    //asloop_check, *attr_wdr_flags);

    if (attr_block_len == 0) {
        return;
    }

    rcv_data = attr_block_data;
    rcv_len = attr_block_len;

    while (rcv_len > 0) {

        filter_action = bgp_upd_filter_get_final_action(bgp);
        if (filter_action == BGP_UPD_FILTER_ACTION_WDR) {
            // Continue parsing if NLRIs have not yet been encountered
            if ((ipv4_reach_len > 0) || (!queue_empty(&bgpinfo_nlriQ))) {
                return;
            }
        }

        err_action = bgp_upd_err_get_final_action(bgp);
        if (BGP_UPD_ERR_ACTION_STOP_MSG(err_action)) {
            return;
        }

        attr_flags = 0;
        attr_code = 0;
        attr_len = 0;
        attr_data = NULL;
        errptr = NULL;
        errlen = 0;

        filter_action = BGP_UPD_FILTER_ACTION_NONE;
        err_action = BGP_UPD_ERR_ACTION_NONE;

        bgp4_rcv_attr_flag(bgp, msg, msg_len,
                           ipv4_reach_len,
                           &rcv_data, &rcv_len,
                           &errptr, &errlen, 
                           &attr_flags, &attr_code,
                           &attr_len, &attr_data,
                           &filter_action, &err_action, 
                           error_ttylist);

        if (BGP_UPD_FILTER_ACTION_STOP_ATTR(filter_action)) {
            continue;
        }

        if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
            continue;
        }

        if (attr_len == 0) {
            err_action = bgp4_rcv_attr_len_zero(bgp,
                                                msg, msg_len, errptr, errlen,
                                                attr_flags, attr_code, attr_len,
                                                error_ttylist);

            if (BGP_UPD_ERR_ACTION_STOP_ATTR(err_action)) {
                continue;
            }
        }

        switch (attr_code) {
        case ATT4_ORIGIN:
            bgp4_rcv_origin(bgp,
                            msg, msg_len, errptr, errlen,
                            attr_data, attr_len, attr_flags,
                            msgin_pathptr,
                            error_ttylist);
            break;

        case ATT4_PATH:
            bgp4_rcv_aspath(bgp,
                            msg, msg_len, errptr, errlen,
                            attr_data, attr_len, attr_flags,
                            msgin_pathptr,
                            myas_count, attr_wdr_flags,
                            FALSE, asloop_check,
                            error_ttylist);
            break;

        case ATT4_NEXTHOP:
            /*
             * Parse NEXT_HOP only if the msg contains any ipv4-unicast NLRIs.
             */
            if (ipv4_reach_len > 0) {
                bgp4_rcv_nexthop(bgp,
                                 msg, msg_len, errptr, errlen,
                                 attr_data, attr_len, attr_flags,
                                 msgin_pathptr,
                                 attr_wdr_flags, error_ttylist);
            }

            break;

        case ATT4_EXITDISC:
            bgp4_rcv_exitdisc(bgp,
                              msg, msg_len, errptr, errlen,
                              attr_data, attr_len, attr_flags,
                              msgin_pathptr,
                              error_ttylist);
            break;

        case ATT4_LOCALPREF:
            bgp4_rcv_localpref(bgp,
                               msg, msg_len, errptr, errlen,
                               attr_data, attr_len, attr_flags,
                               msgin_pathptr,
                               error_ttylist);
            break;

        case ATT4_ATOMICAGG:
            bgp4_rcv_atomicagg(bgp,
                               msg, msg_len, errptr, errlen,
                               attr_data, attr_len, attr_flags,
                               msgin_pathptr,
                               error_ttylist);
            break;

        case ATT4_AGGREGATOR:
            bgp4_rcv_aggregator(bgp,
                                msg, msg_len, errptr, errlen,
                                attr_data, attr_len, attr_flags,
                                msgin_pathptr,
                                FALSE, &honor_new_aspath,
                                error_ttylist);
            break;

        case ATT4_COMMUNITY:
            bgp4_rcv_community(bgp,
                               msg, msg_len, errptr, errlen,
                               attr_data, attr_len, attr_flags,
                               msgin_pathptr,
                               FALSE,
                               error_ttylist);
            break;

        case ATT4_EXTCOMM:
            bgp4_rcv_community(bgp,
                               msg, msg_len, errptr, errlen,
                               attr_data, attr_len, attr_flags,
                               msgin_pathptr,
                               TRUE,
                               error_ttylist);
            break;

        case ATT4_CLUSTLIST:
            bgp4_rcv_clusterlist(bgp,
                                 msg, msg_len, errptr, errlen,
                                 attr_data, attr_len, attr_flags,
                                 msgin_pathptr,
                                 same_cluster, attr_wdr_flags,
                                 error_ttylist);
            break;

        case ATT4_ORIGINATOR:
            bgp4_rcv_originator(bgp,
                                msg, msg_len, errptr, errlen,
                                attr_data, attr_len, attr_flags,
                                msgin_pathptr,
                                attr_wdr_flags, error_ttylist);
            break;

        case ATT4_SSA:
            bgp4_rcv_ssa(bgp,
                         msg, msg_len, errptr, errlen,
                         attr_data, attr_len, attr_flags,
                         msgin_pathptr,
                         error_ttylist);
            break;

        case ATT4_CONNECTOR:
            bgp4_rcv_connector(bgp,
                               msg, msg_len, errptr, errlen,
                               attr_data, attr_len, attr_flags,
                               msgin_pathptr,
                               error_ttylist);
            break;

         case ATT4_PMSI:
            bgp4_rcv_pmsi(bgp,
                          msg, msg_len, errptr, errlen,
                          attr_data, attr_len, attr_flags,
                          msgin_pathptr,
                          error_ttylist);
            break;

        case ATT4_PPMP:
            bgp4_rcv_ppmp(bgp,
                          msg, msg_len, errptr, errlen,
                          attr_data, attr_len, attr_flags,
                          msgin_pathptr,
                          error_ttylist);
            break;

        case ATT4_MP_REACH_NLRI:
            bgp4_rcv_mp_reach(bgp,
                              msg, msg_len, errptr, errlen,
                              attr_data, attr_len, attr_flags,
                              msgin_pathptr,
                              attr_wdr_flags,
                              error_ttylist);
            break;

        case ATT4_MP_UNREACH_NLRI:
            bgp4_rcv_mp_unreach(bgp,
                                msg, msg_len, errptr, errlen,
                                attr_data, attr_len, attr_flags,
                                msgin_pathptr,
                                bmsg, upd_len,
                                error_ttylist);
            break;

        case ATT4_NEW_ASPATH:
            bgp4_rcv_aspath(bgp,
                            msg, msg_len, errptr, errlen,
                            attr_data, attr_len, attr_flags,
                            msgin_pathptr,
                            myas_count, attr_wdr_flags,
                            TRUE, asloop_check,
                            error_ttylist);
            break;

        case ATT4_NEW_AGGREGATOR:
            bgp4_rcv_aggregator(bgp,
                                msg, msg_len, errptr, errlen,
                                attr_data, attr_len, attr_flags,
                                msgin_pathptr,
                                TRUE, &honor_new_aspath,
                                error_ttylist);
            break;

        case ATT4_AIGP:
            bgp4_rcv_aigp(bgp,
                          msg, msg_len, errptr, errlen,
                          attr_data, attr_len, attr_flags,
                          msgin_pathptr,
                          error_ttylist);
            break;

        default:
            /*
             * Use errptr/errlen as we need to include the length of the
             * Tag and the Length field while storing the TLV.
             */
            if (unknown_attr_cnt++ == 0) {
                memset(bgprtr_rcv_attrs, 0, sizeof(bgprtr_rcv_attrs));
            }

            bgp4_rcv_unknown(bgp,
                             msg, msg_len, errptr, errlen,
                             attr_flags, attr_code, attr_len,
                             msgin_pathptr,
                             error_ttylist);
            break;
        }
    }

    bgp_debug_ttyprintf(error_ttylist,
                        "--%s--: END: nbr=%s:: msg=0x%08x/%u, updlen=%u, "
                        "attrbl=0x%08x/%u, ipv4reachlen=%u, msginpath=0x%08x, "
                        "asloopcheck=%d, attrwdrfl=0x%08x:: samecluster=%d, "
                        "myascount=%u:: rcvdata=0x%08x/%u, errptr=0x%08x/%u",
                        __FUNCTION__,
                        bgp->neighbor_name,
                        (uint32_t)msg, msg_len, upd_len,
                        (uint32_t)attr_block_data, attr_block_len,
                        ipv4_reach_len, (uint32_t)msgin_pathptr,
                        asloop_check, *attr_wdr_flags, *same_cluster,
                        (myas_count ? *myas_count : 0),
                        (uint32_t)rcv_data, rcv_len,
                        (uint32_t)errptr, errlen);

    filter_action = bgp_upd_filter_get_final_action(bgp);
    if (filter_action == BGP_UPD_FILTER_ACTION_WDR) {
        return;
    }

    err_action = bgp_upd_err_get_final_action(bgp);
    if (BGP_UPD_ERR_ACTION_STOP_MSG(err_action)) {
        return;
    }

    /*
     * Receiving NEW_AGGREGATOR but no AGGREGATOR is an error condition.
     */
    attr = BGP_PATH_TO_ATTR(msgin_pathptr);
    if (attr == NULL) {
        ios_msg_bgp_internal_error("attr is NULL for rcvd attributes");
        return;
    }

    if ((attr->flags & BATTR_AGGREGATOR) == 0 &&
        (attr->flags & BATTR_NEW_AGGREGATOR) != 0) {

        honor_new_aspath = FALSE;
        attr->aggregator_as = 0;
        attr->aggregator_ip = INADDR_ANY;
        attr->flags &= ~BATTR_NEW_AGGREGATOR;

        bgp_debug_ttyprintf(error_ttylist,
                            "UPDATE from %s contains NEW_AGGREGATOR but no "
                            "AGGREGATOR, ignoring NEW_AGGREGATOR and "
                            "NEW_ASPATH",
                            bgp->neighbor_name);
    }

    /*
     * If we received an ASPATH and NEW_ASPATH then we need to merge the two to
     * create one unified aspath.
     */
    if (honor_new_aspath && (attr->flags & BATTR_ASPATH) &&
        (attr->flags & BATTR_NEW_ASPATH)) {
        /*
         * Verify we have both old and new aspath pointers before starting
         * the merge
         */
        if (!attr->aspathptr || !attr->new_aspathptr) {
            bgp_debug_ttyprintf(error_ttylist,
                                "%s%s,skip AS path merge",
                                (!attr->aspathptr) ? " ASpath is NULL" : "",
                                (!attr->new_aspathptr) ?
                                " 4byte ASpath is NULL" : "");
        } else {
            bgp_merge_new_aspath(bgp, attr, error_ttylist);
        }
    }

    return;
}


/*
 * bgp4_rcv_v4prefixes
 *
 * EDT in bgp_util.h.
 */
static void
bgp4_rcv_v4prefixes (bgp_nbrtype *nbr,
                     uint8_t *msg,
                     uint16_t msg_len,
                     uint16_t attr_block_len,
                     uint8_t *ipv4_reach_data,
                     uint16_t ipv4_reach_len,
                     bpathtype *msgin_pathptr,
                     bgp_dbg_ttylist *error_ttylist)
{
    bnlritype              *bgp_nlri = NULL;

    // Just return if no IPv4 NLRI data or attributes data
    if ((ipv4_reach_len == 0) || (attr_block_len == 0)) {
        return;
    }

    // Do nothing if IPv4-Unicast is not applicable
    if (!bgp4_rcv_afi_is_acceptable(nbr, BGP_TYPE_UPDATE,
                                    BGP_AF_IPv4,
                                    BGP_IPv4_ADDRESS_FAMILY, BGP_SAF_UNICAST,
                                    "IPv4 NLRI", error_ttylist)) {
        return;
    }

    bgp_nlri = bnlri_alloc();

    if (bgp_nlri == NULL) {
        (void) bgp_upd_err_handle(nbr, msg, msg_len,
                                  BGP_UPD_ERR_C1_MEM_ALLOC_FAIL,
                                  0, 0, 0,
                                  NULL, 0);
        bgp_upd_err_store_reset_data(nbr,
                                     BGP_NOMEMORY,
                                     BGP_POSTIT_TYPE_NOMEMORY,
                                     0, 0, NULL, 0);
        ios_msg_bgp_nomem_reset("IPv4 NLRI");
        return;
    }

    bgp_nlri->code = BGP_REACHABLE_NLRI;

    bgp_nlri->afi = BGP_AF_IPv4;
    bgp_nlri->rcvd_afi = BGP_IPv4_ADDRESS_FAMILY;
    bgp_nlri->rcvd_safi = BGP_SAF_UNICAST;
    bgp_nlri->nexthop = msgin_pathptr->nexthop;
    bgp_nlri->nlri = ipv4_reach_data;
    bgp_nlri->len = ipv4_reach_len;

    queue_enqueue(&bgpinfo_nlriQ, bgp_nlri);

    return;
}


/*
 * edt: * * bgp_english_attrflags
 *
 * Convert the BATTR_* flags into English, for debugging
 *
 * Return: void
 *
 * Argument: buf
 *   IN    - Buffer in which to put the string representation
 *
 * Argument: len
 *   IN    - Length of buf, in bytes
 *
 * Argument: flags
 *   IN    - Attribute flags to convert/print
 *
 * Argument: nexthop
 *   IN    - Whether a nexthop was present in the path.  This is not included
 *           in the attribute flags, and hence must be passed as a separate
 *           argument.
 */
static void
bgp_english_attrflags (char     *buf,
                       int16_t   len,
                       uint32_t  flags,
                       bool      nexthop)
{
    int   bytes = 0;  /* Number of bytes returned by snprintf                */
    char *ptr = buf;  /* Pointer into buf                                    */

    if (len > 0 && nexthop) {
        bytes = bgp_snprintf(ptr, len, "NEXTHOP+");
        len -= bytes;
    }

    if (len > 0 && (flags & BATTR_METRIC)) {
        ptr += bytes;
        bytes = bgp_snprintf(ptr, len, "MET+");
        len -= bytes;
    }

    if (len > 0 && (flags & BATTR_ORIGIN)) {
        ptr += bytes;
        bytes = bgp_snprintf(ptr, len, "ORG+");
        len -= bytes;
    }

    if (len > 0 && (flags & BATTR_ASPATH)) {
        ptr += bytes;
        bytes = bgp_snprintf(ptr, len, "AS+");
        len -= bytes;
    }

    if (len > 0 && (flags & BATTR_LOCALPREF)) {
        ptr += bytes;
        bytes = bgp_snprintf(ptr, len, "LOCAL+");
        len -= bytes;
    }

    if (len > 0 && (flags & BATTR_AGGREGATOR)) {
        ptr += bytes;
        bytes = bgp_snprintf(ptr, len, "AGG+");
        len -= bytes;
    }

    if (len > 0 && (flags & BATTR_COMMUNITY)) {
        ptr += bytes;
        bytes = bgp_snprintf(ptr, len, "COMM+");
        len -= bytes;
    }

    if (len > 0 && (flags & BATTR_ATOMICAGG)) {
        ptr += bytes;
        bytes = bgp_snprintf(ptr, len, "ATOM+");
        len -= bytes;
    }

    if (len > 0 && (flags & BATTR_EXTCOMM)) {
        ptr += bytes;
        bytes = bgp_snprintf(ptr, len, "EXTCOMM+");
        len -= bytes;
    }

    if (len > 0 && (flags & BATTR_APPGW)) {
        ptr += bytes;
        bytes = bgp_snprintf(ptr, len, "APPGW+");
        len -= bytes;
    }

    if (len > 0) {
        ptr += bytes;
    }

    if (ptr == buf) {
        *ptr = '\0';
    } else {
        /*
         * Remove the "+" on the end
         */
        *(ptr - 1) = '\0';
    }
}


/*
 * bgp4_required_attributes -
 *
 * Verifies if we have received all the required attributes for
 * reachable prefixes. Note that BPATH_NEXTHOP is set when MP_REACH
 * is present. If an attribute is missing, the code is returned.
 */
static inline bool
bgp4_required_attributes (bgp_nbrtype *bgp, bpathtype *rpath,
                          bnlritype *bgp_nlri, uchar_t *missing_attr)
{
    battrtype *attr;
    bool       retcode;

    attr = BGP_PATH_TO_ATTR(rpath);
    retcode = TRUE;

    /*
     * Look for required attributes in path : nexthop
     */
    /* sa_ignore NO_NULL_CHK */
    if (!(rpath->bp_flags & BPATH_NEXTHOP) &&
        !(rpath->bp_flags & BPATH_MP_REACH)) {
        *missing_attr = ATT4_NEXTHOP;
        retcode = FALSE;
    }
    /*
     * If the nlri is not part of MP_[UN]REACH, i.e. its vanilla
     * ipv4 feasible routes' NLRI, check for NEXT_HOP attribute in
     * the received path.
     */
    else if (!(bgp_nlri->flags & BNLRI_MP) &&
             !(rpath->bp_flags & BPATH_NEXTHOP)) {
        *missing_attr = ATT4_NEXTHOP;
        retcode = FALSE;
    }
    /*
     * Look for other required attributes in attr.
     */
    /*sa_ignore NO_NULL_CHK*/
    else if (!(attr->flags & BATTR_ORIGIN)) {
        *missing_attr = ATT4_ORIGIN;
        retcode = FALSE;
    }
    /*sa_ignore NO_NULL_CHK*/
    else if (!(attr->flags & BATTR_ASPATH)) {
        *missing_attr = ATT4_PATH;
        retcode = FALSE;
    }
    /*sa_ignore NO_NULL_CHK*/
    else if (bgp->cfg.is_internal & !(attr->flags & BATTR_LOCALPREF)) {
        *missing_attr = ATT4_LOCALPREF;
        retcode = FALSE;
    }

    return (retcode);
}


/*
 * bgp4_validate_attributes
 *
 * EDT in bgp_util.h.
 */
static void
bgp4_validate_attributes (bgp_nbrtype     *bgp,
                          uint8_t         *msg,
                          uint16_t         msg_len,
                          uint16_t         attr_block_len,
                          bpathtype       *msgin_pathptr,
                          bool             same_cluster,
                          uint32_t        *attr_wdr_flags,
                          bgp_dbg_ttylist *error_ttylist)
{
    bgp_upd_err_action_t    err_action = BGP_UPD_ERR_ACTION_NONE;
    bnlritype *bgp_nlri;
    battrtype *msgin_attr;
    bool       reachable_nlri;
    bool       nexthop;
    uchar_t    missing_attr;

    reachable_nlri = FALSE;
    msgin_attr = BGP_PATH_TO_ATTR(msgin_pathptr);

    // Just return if there was no attribute
    if (attr_block_len == 0) {
        return;
    }

    /*
     * Done with parsing.  Check for truncation and for all mandatory items.
     * Since we could receive multiple AFI/sub-AFI MP_REACH nlris, verify
     * for each of them if we've received the required set of attributes.
     */
    bgp_nlri = queue_peekhead(&bgpinfo_nlriQ);
    for (; bgp_nlri; bgp_nlri = bgp_nlri->next) {
        if (bgp_nlri->code == BGP_REACHABLE_NLRI) {
            reachable_nlri = TRUE;
            /* sa_ignore NO_NULL_CHK */
            if (!bgp4_required_attributes(bgp, msgin_pathptr, bgp_nlri,
                                          &missing_attr)) {
                if (!bgp_debug_list_empty(error_ttylist)) {
                    char buf[BGP_DEBUG_ATTRFLAGS_BUFLEN];

                    if (!(bgp_nlri->flags & BNLRI_MP)) {
                        nexthop = ((msgin_pathptr->bp_flags &
                                    BPATH_NEXTHOP) != 0);
                    } else {
                        nexthop = (((msgin_pathptr->bp_flags &
                                     BPATH_NEXTHOP) != 0) ||
                                   ((msgin_pathptr->bp_flags &
                                     BPATH_MP_REACH) != 0));
                    }

                    bgp_english_attrflags(buf, BGP_DEBUG_ATTRFLAGS_BUFLEN,
                                          msgin_attr->flags,
                                          nexthop);

                    bgp_debug_ttyprintf(error_ttylist, "UPDATE from %s has "
                                        "missing attributes; present: %s",
                                        bgp->neighbor_name, buf);
                }

                err_action = bgp_upd_err_handle(bgp, msg, msg_len,
                                              BGP_UPD_ERR_C2_ATTR_MAND_MISSING,
                                              0, missing_attr, 0,
                                              NULL, 0);
                bgp_upd_err_store_reset_data(bgp,
                                             BGP_NONE,
                                             BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                             BNOT_UPDATE, BNOT_UPDATE_MISSING,
                                             &missing_attr, 1);

                if (BGP_UPD_ERR_ACTION_STOP_MSG(err_action)) {
                    return;
                }
            }
        }
    }

    if (!reachable_nlri) {
        return;
    }

    /*
     * If it is a reflected update, discard the prefix.
     */
    if (same_cluster) {
        if (msgin_pathptr->rrinfo->originator != bgp->nbrinfo.bgp_router_id) {
            BGP_DEBUG_UPD_IN(BGP_AF_NONE, BGP_NBR_TO_VRF_HANDLE(bgp),
                             bgp_nbr_addr(bgp), B_DIR_IN,
                             NULL, 0, BGP_OPT_DFLT, BGP_DBG_LEVEL_DETAIL,
                             "Route reflector in same cluster. "
                             "Reflected update from %s dropped",
                             bgp->neighbor_name);
            *attr_wdr_flags |= BGP_UPD_WDR_REFLECTED;
        }
    }

    /*
     * Handle the received special communities. Mark them.
     */
    bgp_special_community(msgin_pathptr, msgin_attr->commptr);

    return;
}


/*
 * bgp_buginf_attr_unreach
 *
 * Display attribute problems for a received update.
 */
static void
bgp_buginf_attr_unreach (bgp_dbg_ttylist *ttys,
                         uint32_t attr_wdr_flags,
                         bgp_upd_err_action_t err_action)
{
    if ((err_action == BGP_UPD_ERR_ACTION_WDR_OR_RESET) ||
        (err_action == BGP_UPD_ERR_ACTION_WDR)) {
        bgp_debug_ttyprintf(ttys, " malformed update 'treat-as-withdraw';");
    }

    if (attr_wdr_flags == 0) {
        return;
    }

    if (attr_wdr_flags & (BGP_UPD_WDR_NH_LOCAL |
                          BGP_UPD_WDR_MP_NH_LOCAL)) {
        bgp_debug_ttyprintf(ttys, " next-hop is our own address;");
    }

    if (attr_wdr_flags & (BGP_UPD_WDR_NH_NON_CONNECTED |
                          BGP_UPD_WDR_MP_NH_NON_CONNECTED)) {
        bgp_debug_ttyprintf(ttys, " non-connected next-hop;");
    }

    if (attr_wdr_flags & (BGP_UPD_WDR_NH_MARTIAN |
                          BGP_UPD_WDR_MP_NH_MARTIAN)) {
        bgp_debug_ttyprintf(ttys, " martian next-hop;");
    }

    if (attr_wdr_flags & (BGP_UPD_WDR_NH_SEMANTICS |
                          BGP_UPD_WDR_MP_NH_SEMANTICS)) {
        bgp_debug_ttyprintf(ttys, " nexthop has invalid semantics;");
    }

    if (attr_wdr_flags & (BGP_UPD_WDR_NH_INVALID |
                          BGP_UPD_WDR_MP_NH_INVALID)) {
        bgp_debug_ttyprintf(ttys, " nexthop validity cannot be determined;");
    }

    if (attr_wdr_flags & BGP_UPD_WDR_ASPATH_TOO_LONG) {
        bgp_debug_ttyprintf(ttys, " as-path is too long;");
    }

    if (attr_wdr_flags & BGP_UPD_WDR_ASPATH_LOOP) {
        bgp_debug_ttyprintf(ttys, " as-path contains our own AS, or 0;");
    }

    if (attr_wdr_flags & BGP_UPD_WDR_CLUSTER_LOOP) {
        bgp_debug_ttyprintf(ttys, " cluster-list contains our own cluster ID;");
    }

    if (attr_wdr_flags & BGP_UPD_WDR_ORIGINATOR_OWN) {
        bgp_debug_ttyprintf(ttys, " originator is us;");
    }

    if (attr_wdr_flags & BGP_UPD_WDR_REFLECTED) {
        bgp_debug_ttyprintf(ttys, " reflected from the same cluster;");
    }

    return;
}


/*
 * bgp_buginf_rcv_attribute
 *
 * EDT in bgp_util.h
 */
void
bgp_buginf_rcv_attribute (bgp_dbg_ttylist *ttys,
                          bgp_tblctxtype  *table_ctx,
                          battrtype       *attr,
                          brrinfotype     *rrinfo,
                          bnexthoptype    *nexthop)
{
    bthread_ctxtype *thr;
    uint32_t          j;
    uint32_t          count;
    uint32_t          flags;
    char            *comm_buffer;
    char            *extcomm_buffer;
    char             buf[BGP_DBG_PATHATTR_MAXSIZE];  /* attr descriptions
                                                        buffer              */
    size_t           len = 0;                        /* No. of buffer bytes
                                                        used                */
    bgp_extcomm     *extcommunity;
    char             as_buf[ASCII_ASNUMSIZE];        /* AS buffer           */

    if (!bgp_debug_list_empty(ttys) && (table_ctx != NULL)) {
        thr = bgp_thread_context();
        comm_buffer = thr->thr_community_string_buffer;
        extcomm_buffer = thr->thr_extcommunity_string_buffer;

        if (attr == NULL) {
            ios_msg_bgp_internal_error("attr is NULL for rcvd attribute");
            return;
        }

        flags = attr->flags;

        len += bgp_snprintf(buf + len, BGP_DBG_PATHATTR_MAXSIZE - len,
                            "nexthop %s, origin %c",
                            bgp_nexthop2string(nexthop),
                            bgp_originchar(attr->origin));

        if (len < BGP_DBG_PATHATTR_MAXSIZE && (flags & BATTR_LOCALPREF) != 0) {
            len += bgp_snprintf(buf + len, BGP_DBG_PATHATTR_MAXSIZE - len,
                                ", localpref %"PRIu32"", attr->localpref);
        }

        if (len < BGP_DBG_PATHATTR_MAXSIZE && (flags & BATTR_METRIC) != 0) {
            len += bgp_snprintf(buf + len, BGP_DBG_PATHATTR_MAXSIZE - len,
                                ", metric %u", attr->metric);
        }

        if (len < BGP_DBG_PATHATTR_MAXSIZE && (flags & BATTR_ATOMICAGG) != 0) {
            len += bgp_snprintf(buf + len, BGP_DBG_PATHATTR_MAXSIZE - len,
                                ", atomic-aggregate");
        }

        if (len < BGP_DBG_PATHATTR_MAXSIZE &&
            (flags & BATTR_AGGREGATOR) != 0) {
            (void)bgp_util_asn_print(as_buf, sizeof(as_buf),
                                     0, attr->aggregator_as);
            len += bgp_snprintf(buf + len, BGP_DBG_PATHATTR_MAXSIZE - len,
                                ", aggregated by %s %s", as_buf,
                                bgp_ntoa_r(attr->aggregator_ip));
        }

        if (len < BGP_DBG_PATHATTR_MAXSIZE && rrinfo != NULL) {
            len += bgp_snprintf(buf + len, BGP_DBG_PATHATTR_MAXSIZE - len,
                                ", originator %s",
                                bgp_ntoa_r(rrinfo->originator));
            if (len < BGP_DBG_PATHATTR_MAXSIZE &&
                rrinfo->clusterlength != NULL) {
                count = (rrinfo->clusterlength) >> 2;
                len += bgp_snprintf(buf + len, BGP_DBG_PATHATTR_MAXSIZE - len,
                                    ", clusterlist");
                for (j = 0; j < count && len < BGP_DBG_PATHATTR_MAXSIZE; ++j) {
                    len += bgp_snprintf(buf + len,
                                        BGP_DBG_PATHATTR_MAXSIZE - len, " %s",
                                        bgp_ntoa_r(rrinfo->clusterlist[j]));
                }
            }
        }

        if (len < BGP_DBG_PATHATTR_MAXSIZE && attr->aspathptr != NULL) {
            len += bgp_snprintf(buf + len, BGP_DBG_PATHATTR_MAXSIZE - len,
                                ", path %s", bgp_path2string(attr->aspathptr));
        }

        if ((len < BGP_DBG_PATHATTR_MAXSIZE) &&
            (attr->commptr != NULL) && ((flags & BATTR_COMMUNITY) != 0)) {
            /*
             * The second parameter of this function must be kept up to date
             * with the length of the string in bgp_ctxtype.
             */
            (void)bgp_community_print_array(comm_buffer,
                                            BGP_COMMUNITY_MAX_STRSIZE,
                                            attr->commptr->community,
                                            attr->commptr->comcount);
            len += bgp_snprintf(buf + len, BGP_DBG_PATHATTR_MAXSIZE - len,
                                ", community %s", comm_buffer);
        }

        if (len < BGP_DBG_PATHATTR_MAXSIZE) {
            if ((attr->extcommptr != NULL) && ((flags & BATTR_EXTCOMM) != 0)) {
                extcommunity = attr->extcommptr->extcommunity;
                bgp_extcomm_print_array((uint8_t *)(extcommunity->value),
                                    EXTCOMM_LEN(attr->extcommptr->extcomcount),
                                    BGP_EXTCOMM_MAX_STRSIZE,
                                    extcomm_buffer);
                len += bgp_snprintf(buf + len, BGP_DBG_PATHATTR_MAXSIZE - len,
                                    ", extended community %s", extcomm_buffer);
                if (attr->vd != 0) {
                    len += bgp_snprintf(buf + len,
                                        BGP_DBG_PATHATTR_MAXSIZE - len,
                                        " VD:%u", attr->vd);
                }
            } else if (attr->vd != 0) {
                len += bgp_snprintf(buf + len,
                                    BGP_DBG_PATHATTR_MAXSIZE - len,
                                    ", extended community VD:%u", attr->vd);
            }
        }

        if ((len < BGP_DBG_PATHATTR_MAXSIZE) && ((flags & BATTR_SSA) != 0) &&
            (attr->ssaptr != NULL)) {
            len += bgp_snprintf(buf + len,
                                BGP_DBG_PATHATTR_MAXSIZE - len,
                                ", ");
            ip_opaque_data_string(IP_OPAQUE_TYPE_TUNNEL_SAFI,
                                  sizeof(ipvpn_fwd_params_t),
                                  (uchar_t *)&attr->ssaptr->fwd_params,
                                  buf + len);
        }

        if (len < BGP_DBG_PATHATTR_MAXSIZE && (flags & BATTR_AIGP) != 0) {
            len += bgp_snprintf(buf + len, BGP_DBG_PATHATTR_MAXSIZE - len,
                                ", aigp metric %llu", attr->aigp);
        }

        if (len >= BGP_DBG_PATHATTR_MAXSIZE) {
            buf[BGP_DBG_PATHATTR_MAXSIZE - 1] = 0;
        }

        bgp_debug_ttyprintf(ttys, "%s%s", buf,
                            len >= BGP_DBG_PATHATTR_MAXSIZE ? " WARNING: "
                            "some attributes omitted" : "");
    }
}


static void
bgp4_process_unreachables_dbg_reach (bgp_tblctxtype  *table_ctx,
                                     bgp_nbrtype     *bgp,
                                     int              code,
                                     int              afi,
                                     bgp_dbg_ttylist *pfx_dbg_ttys,
                                     bpathtype       *pathptr,
                                     const char      *prefix_string,
                                     const char      *path_id_str,
                                     uint32_t         attr_wdr_flags,
                                     bool            *shown_attr)
{
    bnexthoptype    *nexthop = NULL;
    brrinfotype     *rrinfo = NULL;

    if (code == BGP_REACHABLE_NLRI) {
        if (pathptr != NULL) {
            rrinfo = pathptr->rrinfo;

            if (pathptr->nexthop != bgprtr_msg_nexthopbuf) {
                nexthop = pathptr->nexthop;
            }
        }

        if (shown_attr && *shown_attr == FALSE) {
            bgp_debug_ttyprintf(pfx_dbg_ttys, "UPDATE from %s with "
                                "attributes:", bgp->neighbor_name);
            /*sa_ignore NO_NULL_CHK*/
            bgp_buginf_rcv_attribute(pfx_dbg_ttys, table_ctx,
                                     BGP_PATH_TO_ATTR(pathptr),
                                     rrinfo, nexthop);
            *shown_attr = TRUE;
        }
        bgp_debug_ttyprintf(pfx_dbg_ttys,
                            "UPDATE from %s, prefix %s (path ID: %s) DENIED "
                            "due to: ",
                            bgp->neighbor_name, prefix_string, path_id_str);

        bgp_buginf_attr_unreach(pfx_dbg_ttys,
                                attr_wdr_flags,
                                bgp_upd_err_get_final_action(bgp));
    } else {
        bgp_debug_ttyprintf(pfx_dbg_ttys,
                            "UPDATE from %s, prefix %s (path ID: %s) withdrawn",
                            bgp->neighbor_name, prefix_string, path_id_str);
    }
}


/*
 * bgp4_process_unreachables
 *
 * Handle the withdrawn part of the received update.
 * When there is attr. error, we treat reachable prefixes as unreachable
 * and call this routine. The attributes are passed to generate debug
 * information in that case.
 */
static void
bgp4_process_unreachables (bgp_nbrtype *bgp,
                           uchar_t     *msg,
                           uint16_t     msg_size,
                           bnlritype   *bgp_nlri,
                           bpathtype   *msgin_pathptr,
                           uint32_t     nlri_attr_wdr_flags,
                           uint8_t      nlri_attr_code,
                           uint32_t     nlri_err_flag,
                           uint8_t      filter_action,
                           bgp_upd_err_action_t err_action,
                           bool         debug,
                           bool        *net_debug_match)
{
    bnettype        *net;
    bpfxtype         prefix;
    bgp_afnbrtype   *bgp_af;
    bpathtype       *path;
    bpathtype       *npath;
    battrtype       *attr;
    battrtype       *attr_best;
    bgp_tblattrtype *tblattr_best;
    bool             shown_attr;
    bool             do_bestpath;
    bgp_ctxtype     *bgp_ctx;
    bnexthoptype    *old_nexthop;
    uchar_t          afi;
    uchar_t          entry_size;
    bgp_dbg_ttylist  pfx_dbg_ttys;
    const char      *prefix_string;
    bool             charge_penalty;
    bool             do_debug;
    bgp_tblctxtype  *table_ctx;
    bgp_rdinfotype  *rdinfo;             /* rdinfo associated with the table */
    char             path_id_str[32];
    bool             need_unlock_rdinfo;

    afi = bgp_nlri->afi;
    table_ctx = BGP_NBR_TO_TABLE_CTX(bgp, afi);
    bgp_ctx = table_ctx->bgp_ctx;
    bgp_af = bgp->af[afi];
    shown_attr = FALSE;
    prefix_string = NULL;
    do_debug = FALSE;
    path_id_str[0] = '\0';
    bzero(&prefix, sizeof(prefix));
    need_unlock_rdinfo = FALSE;

    BGP_DEBUG_UPD_IN(afi, BGP_TABLE_CTX_TO_VRF_HANDLE(table_ctx),
                     bgp_nbr_addr(bgp), B_DIR_IN, NULL, 0, BGP_OPT_DFLT,
                     BGP_DBG_LEVEL_DETAIL,
                     "Received unreachables from %s: attrcode=%u, "
                     "attrwdrflags=0x%08x",
                     bgp->neighbor_name, nlri_attr_code, nlri_attr_wdr_flags);

    if (bgp_ctx == NULL) {
        return;
    }

    /*
     * If addpath is enabled, mark it in the prefix flags.
     */
    if ((bgp_af->af2_flags & BN_AF2_ADDPATH_RECV) != 0) {
        prefix.flags |= BGP_PFX_FLAGS_ADDPATH;
    }

    while (bgp_nlri->len > 0) {

        attr_best = NULL;
        tblattr_best = NULL;
        do_bestpath = FALSE;

        if ((prefix.flags & BGP_PFX_FLAGS_ADDPATH) != 0) {
            if (bgp_nlri->len < BGP_ADDPATH_NLRI_OVERHEAD) {
                (void) bgp_upd_err_handle(bgp, msg, msg_size,
                                          nlri_err_flag,
                                          0, nlri_attr_code, 0,
                                          bgp_nlri->nlri, 1);
                bgp_upd_err_store_reset_data(bgp,
                                             BGP_NONE,
                                             BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                             BNOT_UPDATE, BNOT_UPDATE_NETWORK,
                                             bgp_nlri->nlri, 1);
                BGP_DEBUG_UPD_IN(afi, BGP_TABLE_CTX_TO_VRF_HANDLE(table_ctx),
                                 bgp_nbr_addr(bgp), B_DIR_IN, NULL, 0,
                                 BGP_OPT_DFLT, BGP_DBG_LEVEL_WARNING,
                                 "Invalid prefix received in %s from %s",
                                 bgp_nlri->code == BGP_REACHABLE_NLRI ?
                                 " update" : " withdraw", bgp->neighbor_name);
                return;
            }
        }

        /*
         * Read one NLRI at a time and populate the prefix structure
         * with prefix/prefixlen as well as AF dependent information
         * linke BGP label, RD etc.
         */
        entry_size = bgp_readprefix(table_ctx, bgp_nlri->rcvd_safi,
                                    bgp_nlri->nlri, &prefix);

        if (!entry_size) {
            (void) bgp_upd_err_handle(bgp, msg, msg_size,
                                      nlri_err_flag,
                                      0, nlri_attr_code, 0,
                                      bgp_nlri->nlri, 1);
            bgp_upd_err_store_reset_data(bgp,
                                         BGP_NONE,
                                         BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                         BNOT_UPDATE, BNOT_UPDATE_NETWORK,
                                         bgp_nlri->nlri, 1);
            BGP_DEBUG_UPD_IN(afi, BGP_TABLE_CTX_TO_VRF_HANDLE(table_ctx),
                             bgp_nbr_addr(bgp), B_DIR_IN, NULL, 0,
                             BGP_OPT_DFLT, BGP_DBG_LEVEL_WARNING,
                             "Invalid prefix received in %s from %s",
                             bgp_nlri->code == BGP_REACHABLE_NLRI ?
                             " update" : " withdraw", bgp->neighbor_name);
            return;
        }

        /*
         * Make sure that we are not exceeding the bounds of the nlri list
         */
        if (bgp_nlri->len < entry_size) {
            (void) bgp_upd_err_handle(bgp, msg, msg_size,
                                      nlri_err_flag,
                                      0, nlri_attr_code, 0,
                                      bgp_nlri->nlri, 1);
            bgp_upd_err_store_reset_data(bgp,
                                         BGP_NONE,
                                         BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                         BNOT_UPDATE, BNOT_UPDATE_NETWORK,
                                         bgp_nlri->nlri, 1);
            BGP_DEBUG_UPD_IN(afi, BGP_TABLE_CTX_TO_VRF_HANDLE(table_ctx),
                             bgp_nbr_addr(bgp), B_DIR_IN, NULL, 0,
                             BGP_OPT_DFLT, BGP_DBG_LEVEL_WARNING,
                             "NLRI-list length mismatch in "
                             "%s from %s",
                             bgp_nlri->code == BGP_REACHABLE_NLRI ?
                             " update" : " withdraw", bgp->neighbor_name);
            return;
        }

        bgp_nlri->len -= entry_size;
        bgp_nlri->nlri += entry_size;

        if (debug) {
            bgp_debug_ttys(&pfx_dbg_ttys, BGP_DEBUG_FLAG_UPD_IN, afi,
                           BGP_TABLE_CTX_TO_VRF_HANDLE(table_ctx),
                           &bgp->nbrinfo.nbr_addr, B_DIR_IN, prefix.network,
                           prefix.masklen, NULL, NULL, BGP_OPT_DFLT,
                           BGP_DBG_LEVEL_DETAIL);

            if (!bgp_debug_list_empty(&pfx_dbg_ttys)) {
                *net_debug_match = TRUE;
                do_debug = TRUE;
            }
        }


        if ((do_debug) ||
            (filter_action != BGP_UPD_FILTER_ACTION_NONE) ||
            (err_action != BGP_UPD_ERR_ACTION_NONE)) {

            prefix_string = bgp_get_prefix_string(afi, &prefix);

            if ((prefix.flags & BGP_PFX_FLAGS_ADDPATH) != 0) {
                snprintf(path_id_str, sizeof(path_id_str), "%u",
                         prefix.path_id);
            } else {
                snprintf(path_id_str, sizeof(path_id_str), "%s",
                         "none");
            }
        } else {
            prefix_string = NULL;
            path_id_str[0] = '\0';
        }

        /*
         * Validate the received prefix
         */
        if (!bgp_verify_prefix(table_ctx, &prefix, NULL, NULL, bgp)) {
            if (do_debug) {
                bgp_debug_ttyprintf(&pfx_dbg_ttys,
                                    "Martian network %s (path ID: %s) in %s "
                                    "from %s",
                                    prefix_string, path_id_str,
                                    (bgp_nlri->code == BGP_REACHABLE_NLRI ?
                                        "update" : "withdraw"),
                                    bgp->neighbor_name);
            }
            continue;
        }

        if (filter_action != BGP_UPD_FILTER_ACTION_NONE) {
            bgp_upd_filter_store_nlri(bgp, afi, prefix_string);
        }

        if (err_action != BGP_UPD_ERR_ACTION_NONE) {
            bgp_upd_err_store_nlri(bgp, afi, prefix_string);
        }

        if (do_debug) {
            bgp4_process_unreachables_dbg_reach(table_ctx, bgp, bgp_nlri->code,
                                                afi, &pfx_dbg_ttys,
                                                msgin_pathptr, prefix_string,
                                                path_id_str,
                                                nlri_attr_wdr_flags,
                                                &shown_attr);
        }

        /*
         * See if network is in BGP database.
         *
         * If the mp_unreach is coming from the PE neighbor, find the rdinfo
         * associated with the vpnv4 unicast prefix first.
         */
        if (table_ctx->rdinfo == NULL) {
            rdinfo = bgp_rdinfo_lookup(bgp_ctx, prefix.rd);
            if (rdinfo == NULL) {
                /*
                 * If we don't have matching rdinfo, skip this vpnv4 prefix
                 */
                continue;
            } else {
                /*
                 * lock the rd info so rd won't get deleted before release
                 * the sync lock
                 */
                bgp_rdinfo_lock(rdinfo);
                need_unlock_rdinfo = TRUE;

                /*
                 * Unlock the rd node before we perform a lookup for net
                 */
                bgp_rdinfo_sync_unlock(rdinfo);
            }
        } else {
            rdinfo = BGP_TABLE_CTX_TO_RDINFO(table_ctx);
        }

        /*
         * Add rdinfo to the bump list
         */
        if (bgp_rdinfo_not_on_bump_list(rdinfo,
                                        BGP_RDINFO_BUMP_FLAG_RTR_THREAD)) {
            bgp_rdinfo_add_to_bump_list(&bgpinfo_rtr_rdinfo_bump_list,
                                        BGP_RDINFO_BUMP_FLAG_RTR_THREAD,
                                        rdinfo);
        }

        /*
         * We can unlock the rdinfo here since it will not have chance
         * to get deleted (it is on the bump list already)
         */
        if (need_unlock_rdinfo) {
            need_unlock_rdinfo = FALSE;
            bgp_rdinfo_unlock(rdinfo);
        }

        net = bgp_lookup_prefix(table_ctx, rdinfo, &prefix);
        if (net == NULL) {
            /*
             * We don't have matching net
             */
            continue;
        }

        path = bgp_find_rcvd_path(net, &(bgp->nbrinfo), prefix.path_id);
        if (path == NULL) {
            /*
             * We don't have a path. Unlock the net and go to next NLRI
             */
            goto next;
        }

        /*
         * If there was a path, update the accepted prefix count for the
         * neighbor.
         */
        bgp_rcvd_prefix_decr(bgp, table_ctx, net, path);
        attr = BGP_PATH_TO_ATTR(path);
        path->bp_flags &= ~BPATH_VALID;
        tblattr_best = bgp_bestpath_attr(net, &old_nexthop);
        do_bestpath = FALSE;

        if (bgp_af->af_flags & BN_AF_SOFT_RECONFIG_INOK) {
            /*
             * If received entry alone, blow it away, decrease the
             * received-only route count and continue.
             * If this is both received and used, there is no need
             * to clear the BPATH_CLEAR_RCVD flag. Otherwise the net version
             * does not get bumped in bgp_delete_path() and therefore the
             * change is not picked up by RIB. So we just fall thru.
             * Or else check if there is the next path is from this
             * neighbor. If so, it is rcvd path, blow it away and
             * fall thru.
             */
            if (path->bp_flags & BPATH_RCVD_ONLY) {
                bgp_delete_path(table_ctx, net, &path, TRUE, TRUE, FALSE);
                goto next;
            } else if (!(path->bp_flags & BPATH_RCVD_USED)) {
                if (BGP_PATH_NEXT_IS_SOFT(path)) {
                    npath = path->next;
                    bgp_delete_path(table_ctx, net, &npath, TRUE, FALSE, FALSE);
                }
            }
        }

        bgp_tblattr_lock(tblattr_best);

        bgp_nexthop_lock(old_nexthop, NULL);

        /*
         * Note that external paths can be dampened.
         */
        if (table_ctx->dampening && !bgp->cfg.is_internal) {
            charge_penalty = bgp_charge_penalty(table_ctx, net, path);
            if (!charge_penalty) {
                ios_msg_bgp_nomem_reset("dampening penalty");
                bgp_tblattr_unlock(table_ctx, tblattr_best);
                bnet_sync_unlock(net);

                (void) bgp_upd_err_handle(bgp, msg, msg_size,
                                          BGP_UPD_ERR_C1_MEM_ALLOC_FAIL,
                                          0, 0, 0, NULL, 0);
                bgp_upd_err_store_reset_data(bgp,
                                             BGP_NOMEMORY,
                                             BGP_POSTIT_TYPE_NOMEMORY,
                                             BNOT_NONE, 0, NULL, 0);
                return;
            }

            path->bp_flags |= BPATH_HISTORY;
            table_ctx->table_info.sn_hist_paths++;

            if (SPEAKER_DO_GROUP_BESTPATH(net, path)) {
                do_bestpath = TRUE;
            }
        } else {
            if (SPEAKER_DO_GROUP_BESTPATH(net, path)) {
                do_bestpath = TRUE;
            }
            bgp_delete_path(table_ctx, net, &path, TRUE, FALSE, FALSE);
        }
        
        if (do_bestpath) {
            bgp_bestpath(rdinfo->table_ctx, net, path, tblattr_best,
                         old_nexthop,
                         BNET_NEED_RIB_PROCESSING + BNET_NEED_UPD_PROCESSING +
                         BNET_NEED_IMP_PROCESSING + BNET_NEED_BRIB_PROCESSING);
        }
        bgp_tblattr_unlock(table_ctx, tblattr_best);
        bgp_nexthop_unlock(old_nexthop, NULL);
    next:
        bnet_sync_unlock(net);
    }

    // NOTE: Below error-handling is probably not needed...
    if (bgp_nlri->len != 0) {
        (void) bgp_upd_err_handle(bgp, msg, msg_size,
                                  nlri_err_flag,
                                  0, nlri_attr_code, 0,
                                  NULL, 0);
        bgp_upd_err_store_reset_data(bgp,
                                     BGP_NONE,
                                     BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                     BNOT_UPDATE, BNOT_UPDATE_MALFORMED,
                                     NULL, 0);
        BGP_DEBUG_UPD_IN(afi, BGP_TABLE_CTX_TO_VRF_HANDLE(table_ctx),
                         bgp_nbr_addr(bgp), B_DIR_IN, NULL, 0,
                         BGP_OPT_NOFILTER, BGP_DBG_LEVEL_ERROR,
                         "Synchronization error processing withdrawn NRLI");

        return;
    }

    return;
}


/*
 * bgp4_update_existing_path
 *
 * NOTE: This function should return TRUE *always* except when there is
 *       a memory allocation failure.
 *
 */
static bool
bgp4_update_existing_path (bgp_tblctxtype   *table_ctx,
                           bgp_nbrtype      *bgp,
                           bnettype         *net,
                           bpathtype        *rcvd_path,
                           bpathtype        *old_path,
                           bgp_tblattrtype  *rcvd_tblattr,
                           bool             *duplicate,
                           bgp_tblattrtype **tblattr_best,
                           bnexthoptype    **old_nexthop,
                           brrinfotype      *rrinfo,
                           bnexthoptype     *nexthop)
{
    battrtype       *attr;
    bgp_afnbrtype   *nbr_rt_const_af;
    /*
     * If multiple parents and duplicate, the rcv_attr from
     * this neighbor could have changed but resulting in same
     * set_attr. Example : rcv MED changed but have inbound set
     * MED. Blow the parent list.
     */
    /*sa_ignore NO_NULL_CHK*/
    if (bgp_identical_path(table_ctx, old_path, rcvd_path, rcvd_tblattr, rrinfo,
                           nexthop)) {
        BGP_DEBUG_UPD_IN(
            table_ctx->parent_afi,
            BGP_TABLE_CTX_TO_VRF_HANDLE(table_ctx),
            bgp_nbr_addr(bgp), B_DIR_IN,
            bgp_net2nptr(net), bgp_net2pfxlen(net), BGP_OPT_DFLT,
            BGP_DBG_LEVEL_DETAIL, "%s: duplicate path (%s) "
            "ignored", bgp_bnet2string(table_ctx, net, TRUE),
            bgp_bpath_to_aspath_string(old_path));

        /*
         * If multiple parents and duplicate, the rcv_attr from this
         * neighbor could have changed but resulting in same
         * set_attr. Example : rcv MED changed but have inbound
         * set-MED. Blow the parent list.
         */
        *duplicate = TRUE;
        /*
         * For legacy PE with GR, the nbr RTs and RT SAFI nets corresponsding
         * to the vpn net are blown away on reset, so reconstruct them here.
         */
        if (bgp_afi_is_for_vpn_table(table_ctx->afi)) {
            attr = BGP_PATH_TO_ATTR(rcvd_path);
            nbr_rt_const_af = bgp->af[BGP_AF_RT_CONSTRAINT];
            if (attr && 
                ((attr->flags & BATTR_LEGACY_PE_RT) != 0) &&
                (nbr_rt_const_af != NULL) &&
                ((nbr_rt_const_af->af2_flags & BN_AF2_NBR_LEGACY_PE_RT) != 0)) {
              bgp_rt_constrt_replace_legacy_pe_path(net, old_path, rcvd_path, 
                                                    FALSE);
            }
        }
        return (TRUE);
    }
    
    *duplicate = FALSE;

    /*
     * We may need to do bestpath.  This will require the old
     * nexthop and tblattr.  Lock them for use with
     * bgp_bestpath()
     */
    *tblattr_best = bgp_bestpath_attr(net, old_nexthop);
    bgp_tblattr_lock(*tblattr_best);
    bgp_nexthop_lock(*old_nexthop, NULL);

    if (table_ctx->dampening && !bgp->cfg.is_internal) {
        if (!bgp_damp_update(table_ctx, bgp, net, rcvd_path, rcvd_tblattr,
                             old_path, nexthop)) {
            ios_msg_bgp_nomem_reset("dampening info");
            bnet_sync_unlock(net);
            return(FALSE);
        }
    } else {
        /*
         * If we're going to replace the existing path with the received
         * path, then we're going to lose track of whether the old path
         * was received with a label or not.  For the purposes of counting
         * bestpaths, we consider labeled and non-labeled paths in the
         * same table to belong to different AFs.  So, if the old path was
         * the bestpath, assume for now that the new path is best and
         * update bestpath counters accordingly.  The counter for the new
         * path will get "fixed" when we call bgp_count_bestpath_change()
         * after computing the new bestpath.
         */
        if (old_path == BNET_BESTPATH(net)) {
            bgp_count_bestpath_change(table_ctx, old_path, rcvd_path,
                                      BGP_PATH_SELECT_BESTPATH);

            /*
             * Non-identical valid path is received. Replace the existing
             * path with the new one. Perform old attribute cleanup prior
             * to replace if path is the best. On path modify, the bestpath
             * attribute is changed so we need to decrement the bestpath
             * count for the old  attribute before we add the new attribute.
             * We will update the net->bestpath when we call bgp_bestpath()
             * later.
             * Also the decrement needs to be performed only if the attr/key
             * changes on the replaced path, if not the decrement/increment
             * is not necessary, hence pass in the rcvd_tblattr for this case.
             */
            bgp_change_bestpath(table_ctx, net, NULL, rcvd_tblattr, FALSE);
        }

        if (bgp_afi_is_for_vpn_table(table_ctx->afi)) {
            attr = BGP_PATH_TO_ATTR(rcvd_path);
            nbr_rt_const_af = bgp->af[BGP_AF_RT_CONSTRAINT];
            if (attr && 
                ((attr->flags & BATTR_LEGACY_PE_RT) != 0) &&
                (nbr_rt_const_af != NULL) &&
                ((nbr_rt_const_af->af2_flags & BN_AF2_NBR_LEGACY_PE_RT) != 0)) {
              bgp_rt_constrt_replace_legacy_pe_path(net, old_path, rcvd_path, 
                                                    TRUE);
            }
        }

        bgp_replace_path(table_ctx, net, old_path, rcvd_path, rcvd_tblattr,
                         rrinfo, nexthop, bgp_nbrinfo(bgp));
    }

    return (TRUE);
}


/*
 * bgp4_restore_attribute
 * EDT in bgp_util.h
 */
void
bgp4_restore_attribute (bgp_tblctxtype      *table_ctx,
                        const bpathtype     *msgin_pathptr,
                        bpathtype           *work_path,
                        uint32_t              attr_changed)
{
    battrtype       *msgin_attr;
    battrtype       *work_attr;
    baspathtype     *msgin_aspath;
    baspathtype     *work_aspath;
    bcommtype       *msgin_comm;
    bcommtype       *work_comm;
    bextcommtype    *msgin_extcomm;
    bextcommtype    *work_extcomm;
    bnexthoptype    *msgin_nexthop;
    bnexthoptype    *work_nexthop;
    bgp_tblattrtype *work_tblattr;

    /*
     * Set up some convenience pointers to the attributes, AS paths,
     * community/extcommunity lists of the routes passed in
     */
    msgin_attr = BGP_PATH_TO_ATTR(msgin_pathptr);
    work_attr = BGP_PATH_TO_ATTR(work_path);
    /* sa_ignore NO_NULL_CHK */
    work_tblattr = work_path->tblattr;

    /*sa_ignore NO_NULL_CHK*/
    msgin_aspath = msgin_attr->aspathptr;
    /*sa_ignore NO_NULL_CHK*/
    work_aspath = work_attr->aspathptr;

    msgin_comm = msgin_attr->commptr;
    work_comm = work_attr->commptr;

    msgin_extcomm = msgin_attr->extcommptr;
    work_extcomm = work_attr->extcommptr;

    /* sa_ignore NO_NULL_CHK */
    msgin_nexthop = msgin_pathptr->nexthop;
    work_nexthop = work_path->nexthop;

    /*
     * If any of the attributes have changed, copy the original path &
     * attribute structures over the working copies (being careful that the
     * pointers in the working copies don't get overwritten)
     */
    if (attr_changed != 0) {
        bgp_attr_copy(work_attr, msgin_attr);
        memcpy(work_path, msgin_pathptr, table_ctx->bgp_ctx->bpathsize);
        bgp_copy_nexthop(work_nexthop, msgin_nexthop);
        work_path->tblattr = work_tblattr;
        /* sa_ignore NO_NULL_CHK */
        bgp_prepare_worktblattr(work_path->tblattr, work_attr);
        work_path->nexthop = work_nexthop;
    }
    /*
     * If the AS path changed, copy across the old path
     */
    if ((attr_changed & BGP_ASPATH_CHANGED) != 0) {
        memcpy(work_aspath->aspath, msgin_aspath->aspath,
               msgin_aspath->aslength);
        work_aspath->aslength = msgin_aspath->aslength;
        work_aspath->neighboras = msgin_aspath->neighboras;
        work_aspath->pathhops = msgin_aspath->pathhops;
    }
    /*
     * If the community list changed, copy across the old list
     */
    if ((attr_changed & BGP_COMMUNITY_CHANGED) != 0) {
        memcpy(work_comm->community, msgin_comm->community,
               COMMUNITY_LEN(msgin_comm->comcount));
        work_comm->comcount = msgin_comm->comcount;
    }
    /*
     * If the extcommunity list changed, copy across the old list
     */
    if ((attr_changed & BGP_EXTCOMM_CHANGED) != 0) {
        memcpy(work_extcomm->extcommunity, msgin_extcomm->extcommunity,
               EXTCOMM_LEN(msgin_extcomm->extcomcount));
        work_extcomm->extcomcount = msgin_extcomm->extcomcount;
    }

}

/*
 * bgp4_process_reachables
 *
 * Process NLRI of an update msg.
 *
 * Get ready to scan the network list. We will copy the whole bpath
 * and attr structures and not try to dance by remembering only some
 * of them and breaking loose.
 * The community and as-path is in global buffers. The length is in
 * the battr structures.
 *
 * General methodology : Don't corrupt rcvdmsg_path,
 * rcvdmsg_attr, rcvd_aspath rcvd_comlist elements.
 * Always work with work_path, work_attr, work_aspath, work_comlist.
 * Copy the work_* by rcvd_* for prefix matching.
 *
 * XXX we should get rid of several global buffers.
 */
static void
bgp4_process_reachables (bgp_nbrtype *bgp,
                         uchar_t     *msg,
                         uint16_t     msg_size,
                         bnlritype   *bgp_nlri,
                         bpathtype   *msgin_pathptr,
                         uint8_t      nlri_attr_code,
                         uint32_t     nlri_err_flag,
                         uint8_t      filter_action,
                         bgp_upd_err_action_t err_action,
                         bool         debug,
                         bool        *net_debug_match)
{
    bnettype           *net;
    bpfxtype            prefix;
    uchar_t             path_buf[bgp_info.max_path_size];
    bpathtype          *work_path;
    bnexthoptype       *work_nexthop;
    uchar_t             nexthop_buf[BNEXTHOP_MAX_SIZE];
    const char         *prefix_string;
    uchar_t             afi;
    uchar_t             entry_size;
    bpathtype          *path;
    battrtype          *attr_entry;       /* Received attribute          */
    bgp_tblattrtype    *tblattr_entry;    /* Received tblattr            */
    battrtype          *msgin_attr;       /* attr passed to this fn      */
    battrtype           work_attr;        /* work copy of attr           */
    bgp_tblattrtype     work_tblattr;     /* work copy of tblattr        */
    battrtype          *attr_nlri;        /* nlri attr, after policy     */
    bgp_tblattrtype    *tblattr_nlri;     /* nlri tblattr, after policy  */
    bgp_tblattrtype    *tblattr_temp;     /* temp tblattr, for same RD   */
    bgp_tblattrtype    *tblattr_nlri_rcv; /* tblattr for rcv only path   */
    brrinfotype        *rrinfo_entry;
    bnexthoptype       *nexthop_entry;
    bool                have_policy;
    bool                have_pfxorf;
    bool                do_bestpath;
    bool                duplicate;
    bool                do_netmatch = FALSE;
    bool                do_rpki_match = FALSE;
    bool                do_rpki_lookup;   // do_rpki_lookup => path requires 
                                          // origin-as validation
    bool                defaultpolicy_permit;
    bool                pfxorf_permit;
    bool                policy_permit;
    bool                shown_attr;
    bool                firsttime;
    uint32_t             net_processed;
    uint32_t             attr_changed;
    bgp_afnbrtype      *bgp_af;
    bgp_ctxtype        *bgp_ctx;
    bgp_tblctxtype     *table_ctx;
    bgp_tblctxtype     *local_table_ctx;
    bgp_attrctxtype    *attr_ctx;
    bgp_rdinfotype     *rdinfo;                     /* Allocated RD node     */
    bnexthoptype       *old_nexthop;
    bgp_tblattrtype    *tblattr_best;
    brrinfotype        *rrinfo;
    bnexthoptype       *nexthop;
    bgp_dbg_ttylist     pfx_dbg_ttys;
    bool                extcomm_permit;
    bool                prefix_independent_permit;
    bool                soft_reconfig;
    brt_flagstype       sets;
    bool                do_debug;
    bool                policy_lock;  /* True if policy lock held */
    uint32_t            oldmetric;
    bnhtype             nh;
    uchar_t             segtype;
    bool                verify_prefix;
    char                path_id_str[32];
    bool                need_unlock_rdinfo;
    uchar_t             l2vpn_pfx[BGP_IPv4_MAXPFXLEN];
    bool                do_import_ao;

    afi = bgp_nlri->afi;
    bgp_af = bgp->af[afi];
    old_nexthop = NULL;
    tblattr_best = NULL;
    verify_prefix = TRUE;
    path_id_str[0] = '\0';
    bzero(&prefix, sizeof(prefix));
    need_unlock_rdinfo = FALSE;
    rdinfo = NULL;
    sets = 0;

    /*
     * Fetch the table_ctx from bgp_nbrtype.
     */
    table_ctx = BGP_NBR_TO_TABLE_CTX(bgp, afi);
    /* sa_ignore NO_NULL_CHK */
    bgp_ctx = table_ctx->bgp_ctx;
    /* sa_ignore NO_NULL_CHK */
    attr_ctx = bgp_ctx->attr_ctx;
    local_table_ctx = NULL;

    /*
     * Validate the afi received
     */
    if ((bgp_ctx == NULL) || (table_ctx == NULL)) {
        return;
    }

    defaultpolicy_permit = TRUE;
    policy_permit = TRUE;
    pfxorf_permit = TRUE;
    firsttime = TRUE;
    net_processed = attr_changed = 0;
    prefix_string = NULL;
    shown_attr = FALSE;
    msgin_attr = BGP_PATH_TO_ATTR(msgin_pathptr);
    attr_nlri = NULL;
    tblattr_nlri = NULL;
    tblattr_nlri_rcv = NULL;
    tblattr_temp = NULL;
    extcomm_permit = TRUE;
    do_debug = FALSE;
    policy_lock = FALSE;
    nexthop = NULL;
    nexthop_entry = NULL;
    work_path = (bpathtype *) &path_buf[0];
    work_nexthop = (bnexthoptype *) &nexthop_buf[0];

    soft_reconfig = ((bgp->flags & BN_REFRESH) == 0 ||
                     (bgp_af->af_flags & BN_AF_SOFT_RECONF_ALWAYS) != 0) &&
        (bgp_af->af_flags & BN_AF_SOFT_RECONFIG_INOK) != 0;

    /*
     * Lock out neighbor-in policy changes while processing this set
     * of NLRI's, NLRI processing can cache the results of the first
     * policy run for re-use on the rest of the nlri's that share the
     * same path attributes. We don't want a policy unbind to come
     * along and wipe out the changes, as this could result in some of
     * the NLRI'S having the attribute changed correctly and the rest
     * of the NLRI's not having any changes so make sure we are
     * consistent by holding the policy_config_group1_read_lock until we
     * are done processing this set of NLRI's.
     */
    bgp_policy_config_group1_read_lock();
    policy_lock = TRUE;
    have_policy = bgp_policy_inuse(bgp_af->cfg.policyin);
    have_pfxorf = bgp_policy_inuse(bgp_af->cfg.policy_pfxorf);

    /*
     * Check whether any matching is performed based on prefix. If none is
     * done, we can assume that the same policy decisions will be applied to
     * all nets in the update; otherwise we have to run policy for each net
     * individually.
     */
    if (have_policy) {
        do_netmatch = bgp_policy_netmatch_performed(bgp_af->cfg.policyin);
    }

    if (have_pfxorf && !do_netmatch) {
        do_netmatch = bgp_policy_netmatch_performed(bgp_af->cfg.policy_pfxorf);
    }

    /*
     * Check to see if we match on validity state at the nbr-in attachpoint
     */
    if (have_policy) {
        do_rpki_match = bgp_policy_matches_rpki_validity_state(bgp_af->cfg.policyin);

        /*
         * If we are matching based on RPKI validity, we have to go through the
         * 'do_netmatch' codepath to account for the RPKI validity of ALL the 
         * NLRI in the update, not just the first one.
         */
        if (do_rpki_match) {
            do_netmatch = TRUE;
        }
    }

    /*
     * Prepare the work attribute.
     */
    bgp_prepare_workattr(msgin_attr, &work_attr,
                         (baspathtype *) bgp_upd_aspath_buffer,
                         (bcommtype *) bgp_upd_com_buffer,
                         (bextcommtype *) bgp_upd_extcomm_buffer,
                         (bssatype *) bgp_upd_ssa_buffer,
                         (bconntype *) bgp_upd_conn_buffer,
                         (bpmsitype *) bgp_upd_pmsi_buffer,
                         (bppmptype *) bgp_upd_ppmp_buffer);
    bgp_prepare_worktblattr(&work_tblattr, &work_attr);

    /*
     * Add the received attribute entry to the attribute_table.
     */
    tblattr_entry = bgp_tblattr_find_or_create(table_ctx, &work_tblattr);
    if (tblattr_entry == NULL) {
        bgp_policy_config_group1_unlock();
        policy_lock = FALSE;
        ios_msg_bgp_nomem_reset("table attribute");
        (void) bgp_upd_err_handle(bgp, msg, msg_size,
                                  BGP_UPD_ERR_C1_MEM_ALLOC_FAIL,
                                  0, 0, 0, NULL, 0);
        bgp_upd_err_store_reset_data(bgp,
                                     BGP_NOMEMORY, BGP_POSTIT_TYPE_NOMEMORY,
                                     BNOT_NONE, 0, NULL, 0);
        return;
    }
    attr_entry = tblattr_entry->attr;

    /*
     * Create rrinfo entry.
     */
    /* sa_ignore NO_NULL_CHK */
    rrinfo = msgin_pathptr->rrinfo;
    if (rrinfo->originator || rrinfo->clusterlength) {
        rrinfo_entry = bgp_find_or_create_rrinfo(attr_ctx,
                                                 msgin_pathptr->rrinfo);
        if (!rrinfo_entry) {
            ios_msg_bgp_nomem_reset("route-reflector info");
            (void) bgp_upd_err_handle(bgp, msg, msg_size,
                                      BGP_UPD_ERR_C1_MEM_ALLOC_FAIL,
                                      0, 0, 0, NULL, 0);
            bgp_upd_err_store_reset_data(bgp,
                                         BGP_NOMEMORY, BGP_POSTIT_TYPE_NOMEMORY,
                                         BNOT_NONE, 0, NULL, 0);
            goto error_return;
        }
    } else {
        rrinfo_entry = NULL;
    }

    /*
     * Remember if we are dealing with a RR client.
     */
    if (bgp_af->af_flags & BN_AF_RR_CLIENT) {
        msgin_pathptr->bp_flags |= BPATH_CLIENT;
    } else {
        msgin_pathptr->bp_flags &= ~BPATH_CLIENT;
    }

    /*
     * Get the received nexthop.
     */
    nexthop_entry = msgin_pathptr->nexthop;

    if (nexthop_entry == NULL) {
        ios_msg_bgp_nomem_reset("path nexthop");
        (void) bgp_upd_err_handle(bgp, msg, msg_size,
                                  BGP_UPD_ERR_C1_MEM_ALLOC_FAIL,
                                  0, 0, 0, NULL, 0);
        bgp_upd_err_store_reset_data(bgp,
                                     BGP_NOMEMORY, BGP_POSTIT_TYPE_NOMEMORY,
                                     BNOT_NONE, 0, NULL, 0);
        goto error_return;
    }

    /*
     * Prepare the work path and the work attribute.
     */
    bgp_prepare_workpath(table_ctx, msgin_pathptr, work_path, &work_tblattr,
                         work_nexthop);
    if (table_ctx->rdinfo == NULL) {
        work_path->bp_flags |= BPATH_VPN_ONLY;
    }

    /*
     * Declare the attribute buffers to policy.
     */
    bgp_policy_instance_prepare(bgp_af->cfg.policyin, work_path);

    /*
     * For eBGP neighbors with no configured inbound policy, the default is to
     * drop all routes
     */
    defaultpolicy_permit = TRUE;
    if (!bgp_commonadmin(&bgp->nbrinfo) && !bgp_nbraf_has_policy_in(bgp_af)) {
        work_path->bp_flags &= ~BPATH_VALID;
        defaultpolicy_permit = FALSE;
    }

    /*
     * See if we need to do any special filtering based on received RT
     * extended communities.  We need to make sure that we initialize the
     * work-attribute and other fields before we do any filtering.  The
     * reason is that we might have already received these prefixes with
     * valid RTs and installed in the table and now a new RT-policy might
     * deny those prefixes.  So we will need to delete the old paths
     * from the table.
     */
    if ((work_path->bp_flags & BPATH_VALID) &&
        !bgp_apply_af_filter(table_ctx, &work_attr, work_path)) {
        work_path->bp_flags &= ~BPATH_VALID;
        extcomm_permit = FALSE;
        if (bgp_afi_is_for_l2vpn_table(afi)) {
            verify_prefix = FALSE;
        }
    }

    /*
     * Prepare export policy instance and set the do_netmatch flag if
     * the export-policy performs per prefix operation.
     */
    if ((work_path->bp_flags & BPATH_VALID) != 0) {
        if (bgp_export_policy_prepare(table_ctx, work_path)) {
            do_netmatch = TRUE;
        }
    }

    /*
     * Remember whether we've already decided (based on criteria other than the
     * NLRI) to drop the route. (When we have NLRI-dependent modifications to
     * the attributes, we need to reset the attributes to the original values
     * (msgin_attr) each time we process a new NLRI. However in restoring the
     * attributes we mustn't forget if we'd decided to drop based on
     * NLRI-independent criteria.)
     *
     * I *strongly* recommend NOT changing the logic of this code unless you
     * fully understand what is going on: it is more subtle than it first
     * appears, and very easy (as I have found) to get wrong!
     *
     * This is quite tricky, so we attempt to use some formal reasoning to
     * ensure it's correct. We write:
     *
     * attr - for the attributes in the update
     *
     * attr_valid(attr) - to indicate whether the attributes pass the
     *   prefix-independent filters (AS path list filtering etc.). For these
     *   purposes we count the 'drop all routes for eBGP with no policy' as a
     *   prefix-independent filter.
     *
     * route_valid(attr, nlri) - to indicate whether the attributes pass the
     *   (possibly) prefix-dependent filters
     *
     * pfxorf(nlri) - to indicate whether 'nlri' is passed by a prefix ORF
     *
     * valid(attr, nlri) - to indicate whether the route should be used, where
     *   valid(attr, nlri) ==    attr_valid(attr)
     *                        && route_valid(attr, nlri)
     *                        && pfxfilter(nlri)
     *
     * new_attr(attr, nlri) - to indicate the new attributes that should be
     * applied to a route. Note that we assume that this is well-defined even
     * when the route is not valid, giving it a value of 'attr' in the case
     * where the route gets filtered out (i.e. !route_valid(attr, nlri)).
     *
     * work_valid - to indicate whether the current work route is marked as
     *   valid
     *
     * work_attr - to indicate the (possibly modified) attributes on the
     *   current work route
     *
     * p_i_p - we write this as an abbreviation for the variable
     * prefix_independent_permit
     *
     * do_netmatch - to indicate whether route_valid and new_attr are dependent
     * on the nlri. This allows us to do optimisation, since:
     *
     * Formula F
     * ---------
     * !do_netmatch => (Forall nlri1, nlri2 :
     *                   route_valid(attr, nlri1) == route_valid(attr, nlri2)
     *                 && new_attr(attr, nlri1) == new_attr(attr, nlri2) )
     */
    prefix_independent_permit = ((work_path->bp_flags & BPATH_VALID) != 0);

    /*
     * At this point:
     *
     *    p_i_p == attr_valid(attr)
     * && policy_permit
     * && firsttime
     * && work_attr == attr
     *
     * i.e. this is our first time round, and the attributes are clean.
     */

    /*
     * If addpath is enabled, mark it in the prefix flags.
     */
    if ((bgp_af->af2_flags & BN_AF2_ADDPATH_RECV) != 0) {
        prefix.flags |= BGP_PFX_FLAGS_ADDPATH;
    }

    /*
     * Get ready to parse the NLRI.
     * Just calculate the length of the nlri section i.e. netlen
     * and the afi and continue processing.
     */
    while (bgp_nlri->len > 0) {
        /*
         * Loop invariant:
         *
         *    p_i_p == attr_valid(attr)
         * && firsttime => (work_attr == attr)
         * && firsttime => policy_permit
         * && !firsttime => (Exists n : policy_permit == route_valid(attr, n)
         *                               && work_attr == new_attr(attr, n) )
         *
         * i.e. if we haven't run policy yet, then the
         * work_attributes are unmodified and policy_permit is true; if we have
         * run it, then policy_permit and work_attributes contain the results
         * thereof.
         */

        /*
         * Ensure that the working copy of the path is marked as valid in the
         * cases where it needs to be. That is:
         *
         * - We're doing prefix-dependent matching, and the route has been
         * passed by all the prefix-independent filters (but may yet get
         * rejected by the prefix-dependent filtering)
         *
         * - We're not doing prefix-dependent matching, and this is the first
         *   time round (in which case policy_permit is TRUE)
         *
         * - We're not doing prefix-dependent matching, and the
         * prefix-dependent filters passed this route (again, meaning
         * policy_permit is TRUE)
         *
         */
        if (do_netmatch) {
            if (prefix_independent_permit) {
                work_path->bp_flags |= BPATH_VALID;
            } else {
                work_path->bp_flags &= ~BPATH_VALID;
            }
            /*
             * Here:
             *
             * (all the above)
             * && do_netmatch => work_valid == p_i_p
             *
             * i.e. in the do_netmatch case, we mark the route as valid-so-far
             * if the prefix-independent filters allow it
             */
        } else {
            if (policy_permit && prefix_independent_permit) {
                work_path->bp_flags |= BPATH_VALID;
            } else {
                work_path->bp_flags &= ~BPATH_VALID;
            }
            /*
             * Here:
             *
             * (all the above)
             * && !do_netmatch => work_valid == (p_i_p && policy_permit)
             *
             * i.e. in the !do_netmatch case, we mark the route as valid-so-far
             * if the prefix-independent filters allow it and we haven't yet
             * run a policy that's forbidden it.
             */
        }

        /*
         * At this point:
         *
         *    p_i_p == attr_valid(attr)
         * && firsttime => (work_attr == attr)
         * && firsttime => policy_permit
         * && !firsttime => (Exists n : policy_permit == route_valid(attr, n)
         *                               && work_attr == new_attr(attr, n) )
         * && do_netmatch => work_valid == p_i_p
         * && !do_netmatch => work_valid == (p_i_p && policy_permit)
         */

        /*
         * Initialize per nlri variables
         */
        do_bestpath = FALSE;
        tblattr_best = NULL;
        old_nexthop = NULL;
        net = NULL;

        if ((prefix.flags & BGP_PFX_FLAGS_ADDPATH) != 0) {
            if (bgp_nlri->len < BGP_ADDPATH_NLRI_OVERHEAD) {
                (void) bgp_upd_err_handle(bgp, msg, msg_size,
                                          nlri_err_flag,
                                          0, nlri_attr_code, 0,
                                          bgp_nlri->nlri, 1);
                bgp_upd_err_store_reset_data(bgp,
                                             BGP_NONE,
                                             BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                             BNOT_UPDATE, BNOT_UPDATE_NETWORK,
                                             bgp_nlri->nlri, 1);
                BGP_DEBUG_UPD_IN(afi, BGP_TABLE_CTX_TO_VRF_HANDLE(table_ctx),
                                 bgp_nbr_addr(bgp), B_DIR_IN, NULL, 0,
                                 BGP_OPT_DFLT, BGP_DBG_LEVEL_WARNING,
                                 "Invalid prefix received in %s from %s",
                                 bgp_nlri->code == BGP_REACHABLE_NLRI ?
                                 " update" : " withdraw", bgp->neighbor_name);
                goto error_return;
            }
        }
       
        entry_size = bgp_readprefix(table_ctx, bgp_nlri->rcvd_safi,
                                    bgp_nlri->nlri, &prefix);

        if (!entry_size) {
            (void) bgp_upd_err_handle(bgp, msg, msg_size,
                                      nlri_err_flag,
                                      0, nlri_attr_code, 0,
                                      bgp_nlri->nlri, 1);
            bgp_upd_err_store_reset_data(bgp,
                                         BGP_NONE,
                                         BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                         BNOT_UPDATE, BNOT_UPDATE_NETWORK,
                                         bgp_nlri->nlri, 1);
            BGP_DEBUG_UPD_IN(afi, BGP_TABLE_CTX_TO_VRF_HANDLE(table_ctx),
                             bgp_nbr_addr(bgp), B_DIR_IN, NULL, 0,
                             BGP_OPT_DFLT, BGP_DBG_LEVEL_ERROR,
                             "Invalid prefix received in update "
                             "from %s", bgp->neighbor_name);
            goto error_return;
        }

        /*
         * Make sure that we are not exceeding the bounds of the nlri list
         */
        if (bgp_nlri->len < entry_size) {
            (void) bgp_upd_err_handle(bgp, msg, msg_size,
                                      nlri_err_flag,
                                      0, nlri_attr_code, 0,
                                      bgp_nlri->nlri, 1);
            bgp_upd_err_store_reset_data(bgp,
                                         BGP_NONE,
                                         BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                         BNOT_UPDATE, BNOT_UPDATE_NETWORK,
                                         bgp_nlri->nlri, 1);
            BGP_DEBUG_UPD_IN(afi, BGP_TABLE_CTX_TO_VRF_HANDLE(table_ctx),
                             bgp_nbr_addr(bgp), B_DIR_IN, NULL, 0,
                             BGP_OPT_DFLT, BGP_DBG_LEVEL_WARNING,
                             "Prefix list exceeds expected length in "
                             "%s from %s",
                             bgp_nlri->code == BGP_REACHABLE_NLRI ?
                             " update" : " withdraw", bgp->neighbor_name);
            goto error_return;
        }

        /*
         * Make a note of what's read so far.
         */
        bgp_nlri->len -= entry_size;
        bgp_nlri->nlri += entry_size;

        net_processed++;

        if (debug) {
            bgp_debug_ttys(&pfx_dbg_ttys, BGP_DEBUG_FLAG_UPD_IN, afi,
                           BGP_TABLE_CTX_TO_VRF_HANDLE(table_ctx),
                           &bgp->nbrinfo.nbr_addr, B_DIR_IN,
                           prefix.network, prefix.masklen, NULL, NULL,
                           BGP_OPT_DFLT, BGP_DBG_LEVEL_DETAIL);

            if (!bgp_debug_list_empty(&pfx_dbg_ttys)) {
                do_debug = TRUE;
                *net_debug_match = TRUE;
            }
        }

        if ((do_debug) ||
            (filter_action != BGP_UPD_FILTER_ACTION_NONE) ||
            (err_action != BGP_UPD_ERR_ACTION_NONE)) {

            prefix_string = bgp_get_prefix_string(afi, &prefix);

            if ((prefix.flags & BGP_PFX_FLAGS_ADDPATH) != 0) {
                snprintf(path_id_str, sizeof(path_id_str),
                         "%u", prefix.path_id);
            } else {
                snprintf(path_id_str, sizeof(path_id_str),
                         "%s", "none");
            }
        } else {
            prefix_string = NULL;
            path_id_str[0] = '\0';
        }

        /*
         * Verify the prefix just read.
         */
        if (verify_prefix &&
          (!bgp_verify_prefix(table_ctx, &prefix, &work_attr, work_path, bgp) 
           || bgp_check_signalling_fail(bgp, afi, &prefix))) {
            if (do_debug) {
                if (prefix_string == NULL) {
                    prefix_string = bgp_get_prefix_string(afi, &prefix);
                }
                bgp_debug_ttyprintf(&pfx_dbg_ttys,
                                    "Martian network %s (path ID: %s) "
                                    "received from %s (ignored)",
                                    prefix_string, path_id_str,
                                    bgp->neighbor_name);
            }
	    
            bgp_af->pfx_denied++;

            /* L2VPN prefix is rejected due to range check, If it already
               existed we need to delete it. Make the work_path invalid, it
               will cause it to fall through the following checks and
               eventually be deleted by bgp_delete_path
             */
            if (bgp_afi_is_for_l2vpn_table(afi)) {
                work_path->bp_flags &= ~BPATH_VALID;
            }  else {
                /* For all other AFIs */
                continue;
            }
        }

        if (filter_action != BGP_UPD_FILTER_ACTION_NONE) {
            bgp_upd_filter_store_nlri(bgp, afi, prefix_string);
        }

        if (err_action != BGP_UPD_ERR_ACTION_NONE) {
            bgp_upd_err_store_nlri(bgp, afi, prefix_string);
        }

        /*
         * Now, we have a valid NLRI.
         * Check inbound prefix based ORF.
         */
        if ((work_path->bp_flags & BPATH_VALID) != 0) {
            if (have_pfxorf) {
                if (bgp_policy_instance_run(table_ctx,
                                            bgp_af->cfg.policy_pfxorf,
                                            NULL, &prefix, msgin_pathptr,
                                            0, 0, AS_SEQUENCE)) {
                    pfxorf_permit = TRUE;
                } else {
                    work_path->bp_flags &= ~BPATH_VALID;
                    pfxorf_permit = FALSE;
                }
            }
        } else {
            pfxorf_permit = TRUE;
        }

        /*
         * The above block is equivalent to writing:
         *
         * work_valid = work_valid && pfxfilter(nlri)
         *
         *
         * That gives us:
         *
         *    p_i_p == attr_valid(attr)
         * && firsttime => (work_attr == attr)
         * && firsttime => policy_permit
         * && !firsttime => (Exists n : policy_permit == route_valid(attr, n)
         *                               && work_attr == new_attr(attr, n) )
         * && do_netmatch => (work_valid == (p_i_p && pfxfilter(nlri)))
         * && !do_netmatch => (work_valid == (p_i_p && policy_permit
         *                                                 && pfxfilter(nlri)))
         */

        /*
         * This takes all the original stuff like path, attr, aspath,
         * community-list and performs the inbound policy operation. It
         * returns the attribute to be used for the path inserted to the
         * prefix. It can return two types of attributes.
         * (1) old cached attribute. This is usable in two cases.
         *      (1) If the received path is invalid and inbound soft
         *          reconfig is configured, then this can be used for the
         *          received-only path.
         *      (2) If the path is valid and attribute did not change, then
         *          the returned attribute can be used for replacing/adding
         *          the path.
         *
         * (2) new attribute cached. This is usable in
         *      (1) When the input path is permitted and modified by the
         *          inbound policy.
         */

        /*#####################################################################
         * BEGIN INLINE PREFIX VALIDATION
         *#####################################################################
         *
         * Do RPKI validation here right before we do the policy run 
         * because the policy can do matching based on validation state.
         * Make sure to consider only external paths.
         */
        do_rpki_lookup = FALSE; // do_rpki_lookup => path requires origin-as 
                                // validation

        if (BPATH_REQUIRES_ORIGIN_AS_VALIDATION(msgin_pathptr, bgp_ctx->afi)) {

            if (bgp_rpki_get_origin_as_validation_disable(table_ctx, &bgp->nbrinfo)) {

                bpath_set_origin_as_validity(msgin_pathptr, 
                                             BGP_RPKI_ORIGIN_AS_VALID, 
                                             TRUE);

            } else {
    
                bgp_ts            tm = {0,0};
                bgp_time          elapsed = {0,0};
                uint32_t          timemicro = 0;
                bgp_rpki_query    query;
    
                /* start timestamp */
                ptimer_gettime(&tm);
    
                if (bgp_workpath2rpki_query(&prefix, 
                                            msgin_pathptr, 
                                            table_ctx, 
                                            &query) == NOERR) {

                    do_rpki_lookup = TRUE;

                    bgp_rpki_table_lock(BGP_AFI_TO_RPKI_INDEX(bgp_ctx->afi));

                    bgp_rpki_lookup(&query);

                    bgp_rpki_table_unlock(BGP_AFI_TO_RPKI_INDEX(bgp_ctx->afi));

                    bpath_set_origin_as_validity(msgin_pathptr, query.result, FALSE);
                    
                }
    
                ptimer_elapsed_time(&elapsed, &tm);
                timemicro = ptimer_get_ms(&elapsed) * 1000;
    
                // timemicro = time elapsed for inline prefix validation. STATS
            }

        } else if (!BPATH_ORIGIN_AS_VALIDITY_IBGP_SIGNALED(msgin_pathptr)) {
            /*
             * If we did not recieve any EXTCOMM with validity signalling
             * from an IBGP peer, then mark the path as valid by default.
             */
            bpath_set_origin_as_validity(msgin_pathptr, 
                                         BGP_RPKI_ORIGIN_AS_VALID, 
                                         FALSE);
        }

        bpath_set_origin_as_validity(work_path, 
        bpath_get_origin_as_validity(msgin_pathptr),
        bpath_get_origin_as_validation_disabled(msgin_pathptr));


        /*#####################################################################
         * END INLINE PREFIX VALIDATION
         *#####################################################################
         */

        if ((firsttime || do_netmatch) &&
            ((work_path->bp_flags & BPATH_VALID) != 0)) {
            /*
             * Combining the condition of the 'if' with what we know to be true
             * from above (dropping things we no longer need):
             *
             *    p_i_p == attr_valid(attr)
             * && do_netmatch => work_valid == (p_i_p && pfxfilter(nlri))
             * && !do_netmatch => work_valid == (p_i_p && policy_permit
             *                                             && pfxfilter(nlri))
             * && (firsttime || do_netmatch)
             * && work_valid
             *
             * From which we can also deduce:
             *
             *    pfxfilter(nlri) && p_i_p
             *
             * (since work_valid is true, and both conditions are necessary for
             * work_valid to be true)
             */

            firsttime = FALSE;
            /*
             * Now we have:
             *
             *    p_i_p == attr_valid(attr)
             * && work_valid
             * && pfxfilter(nlri) && p_i_p
             * && !firsttime
             */


            /*
             * Restore clean copy of attribute and flags for the next
             * prefix. For the first NLRI attr_changed will be 0 and this will
             * be a no-op; putting this call at the start of the loop rather
             * than at the end avoids us having to clean up for the last NLRI.
             */
            bgp4_restore_attribute(table_ctx, msgin_pathptr, work_path,
                                   attr_changed);

            /*
             * Since we have restored the original attributes, now reset
             * the attr_changed flag for the new iteration.
             */
            attr_changed = 0;

            /*
             * The above is equivalent to 'work_attr = attr', giving:
             *
             *    p_i_p == attr_valid(attr)
             * && work_valid
             * && pfxfilter(nlri) && p_i_p
             * && !firsttime
             * && work_attr == attr
             */

            /*
             * Now run the policy, which may be prefix-dependent, and may
             * update attributes.
             */
            if (have_policy) {
                /*
                 * New policy.
                 */
                segtype = bgp_find_nbr_as_segment_type(work_attr.aspathptr);
                if (bgp_policy_instance_run(table_ctx, bgp_af->cfg.policyin,
                                            NULL, &prefix, msgin_pathptr,
                                            bgp->cfg.yoursystem,
                                            bgp_get_my_as(bgp), segtype)) {
                    policy_permit = TRUE;
                    sets =
                        bgp_policy_instance_transcribe(bgp_af->cfg.policyin);
                    attr_changed |= bgp_sets_to_changes(sets);

                    if (attr_changed) {
                        if (bgp->cfg.is_internal &&
                            (attr_changed & BGP_ASPATH_CHANGED) != 0) {
                            /*
                             * Discard AS-path modifications, if any.
                             * This is not quite the right way to
                             * accomplish this.  For completion of the
                             * work post-FCS, see CSCeb30904.
                             */
                            if (msgin_attr->aspathptr != NULL &&
                                msgin_attr->aspathptr->aslength > 0) {
                                memcpy(work_attr.aspathptr->aspath,
                                       msgin_attr->aspathptr->aspath,
                                       msgin_attr->aspathptr->aslength);
                                work_attr.aspathptr->aslength =
                                    msgin_attr->aspathptr->aslength;
                            } else {
                                work_attr.aspathptr->aslength = 0;
                            }
                        }
                    }
                } else {
                    work_path->bp_flags &= ~BPATH_VALID;
                    policy_permit = FALSE;
                }
            }

            /*
             * If we have dropped a path from a (internet) neighbor, and that
             * neighbor had a policy that matched on origin-AS validity state
             * then we have to mark that neighbor as an unconditional candidate
             * for sending a route-refresh when the RPKI database changes.
             *
             * Note: the path that is being dropped must be coming from an eBGP
             * neighbor.
             */
            if (do_rpki_match && BGP_AFI_INTERNET(bgp_ctx->afi)) {
                if (policy_permit != TRUE) {
                    int idx = BGP_AFI_TO_RPKI_INDEX(afi);
                    if (do_rpki_lookup) { // do_rpki_lookup => path requires 
                                          // origin-as validation (eBGP path)
                        bgp->nbrinfo.rpki_refresh[idx] |= BGP_NBRINFO_RPKI_DROP;
                    }   
                }
            }

            if (policy_permit) {

                /*
                 * Based on the config, apply export RT list, SoO and
                 * export policy to the incoming update
                 */
                bgp_apply_export_attributes(table_ctx, &prefix, &work_attr,
                                            work_path, &bgp_af->cfg.soo,
                                            ((bgp_af->af_flags &
                                              BN_AF_SOO_EXTCOMM) != 0),
                                            &attr_changed);


                if (attr_changed & BGP_EXTCOMM_CHANGED) {
                    /*
                     * If the policy set a link-bw ext-comm (which is a
                     * separate field in brttype, then merge it back to
                     * the work_attr.extcomm
                     */
                    bgp_extcomm bw;
                    if (bgp_policy_instance_get_link_bandwidth(
                        bgp_af->cfg.policyin, &bw)) {
                        bgp_extcomm_array_add_link_bandwidth( 
                        work_attr.extcommptr, &bw);
                        work_attr.flags |= BATTR_DMZLINK_EXTCOMM;
                    }
                }

                if (attr_changed) {	
                    /*
                     * If attributes are modified by the inbound policy
                     * or export attribute processing, create a new attribute.
                     */
                    bgp_prepare_worktblattr(&work_tblattr,
                                            &work_attr);
		    
                    if ((sets & BGP_RT_CHANGE_AIGP_POLICY_IGP) != 0) {
                        work_attr.flags |= BATTR_AIGP_POLICY_IGP;
                    } else if ((sets & BGP_RT_CHANGE_AIGP) != 0) {
                        work_attr.flags |= BATTR_AIGP_POLICY_METRIC;
                    }
		   
                    tblattr_nlri =
                        bgp_tblattr_find_or_create(table_ctx,
                                                   &work_tblattr);
                    if (tblattr_nlri == NULL) {
                        ios_msg_bgp_nomem_reset("changed table attribute");
                        (void) bgp_upd_err_handle(bgp, msg, msg_size,
                                                  BGP_UPD_ERR_C1_MEM_ALLOC_FAIL,
                                                  0, 0, 0, NULL, 0);
                        bgp_upd_err_store_reset_data(bgp,
                                                     BGP_NOMEMORY,
                                                     BGP_POSTIT_TYPE_NOMEMORY,
                                                     BNOT_NONE, 0, NULL, 0);
                        goto error_return;
                    }
                    /*
                     * For this path we have incremented the refcount twice,
                     * once for tblattr_entry and once for tblatt_nlri. But
                     * because these two tblattrs end up being the same we
                     * need to decrement the refcount once.
                     */
                    if (tblattr_nlri == tblattr_entry) {
                        bgp_tblattr_unlock(table_ctx, tblattr_nlri);
                    }

                    bnexthop_to_nh(work_nexthop, &nh, afi);

                    nexthop = bgp_find_or_create_nexthop(
                        BNEXTHOP_TO_GW_CTX(work_nexthop),
                        &nh);

                    if (nexthop == NULL) {
                        ios_msg_bgp_nomem_reset("changed nexthop");
                        (void) bgp_upd_err_handle(bgp, msg, msg_size,
                                                  BGP_UPD_ERR_C1_MEM_ALLOC_FAIL,
                                                  0, 0, 0, NULL, 0);
                        bgp_upd_err_store_reset_data(bgp,
                                                     BGP_NOMEMORY,
                                                     BGP_POSTIT_TYPE_NOMEMORY,
                                                     BNOT_NONE, 0, NULL, 0);
                        goto error_return;
                    }
                    if (nexthop == nexthop_entry) {
                        /*
                         * Decrement the refcount to prevent us from getting
                         * confused about whether we obtained the nexhop
                         * via find/create or just copied 'nexthop' from
                         * 'nexthop_entry'.  We already have locked the
                         * nexthop structure once for 'nexthop_entry',
                         * so we don't need a second lock on it.
                         */
                        bgp_nexthop_unlock(nexthop, NULL);
                    }
                }
            }

            /*
             * The above large block is equivalent to:
             *
             * policy_permit = route_valid(work_attr, nlri)
             * work_valid = policy_permit
             *  work_attr = new_attr(work_attr, nlri)
             *
             * (NB in the case where the route gets filtered out
             * (i.e. !route_valid(work_attr, nlri), we assume that work_attr
             * gets set to NOATTR)
             *
             * giving
             *
             *    p_i_p == attr_valid(attr)
             * && work_valid == route_valid(attr, nlri)
             * && work_attr == new_attr(attr, nlri)
             * && policy_permit == route_valid(attr, nlri)
             * && pfxfilter(nlri) && p_i_p
             * && !firsttime
             *
             * from which we can deduce (*):
             *
             *    p_i_p == attr_valid(attr)
             * && work_valid == route_valid(attr, nlri) && pfxfilter(nlri)
             *                                                        && p_i_p
             * && work_attr == new_attr(attr, nlri)
             *
             * and also (trivially, since firsttime is false)
             *
             *    firsttime => (work_attr == attr)
             * && firsttime => policy_permit
             *
             * Furthermore we can show from (*) and the fact that
             * pfxfilter(nlri) and p_i_p are both true:
             *
             * (Exists n : policy_permit == route_valid(attr, n)
             *                           && work_attr == new_attr(attr, n) )
             *
             * and so (trivially):
             *  !firsttime => (Exists n : policy_permit == valid(attr, n)
             *                         && work_attr == new_attr(attr, n) )
             */
        } else {
            /*
             * The negation of the condition in the 'if' is:
             *
             * !((firsttime || do_netmatch) && work_valid)
             *
             * or
             *
             * !(firsttime || do_netmatch) || !work_valid
             *
             * or
             *
             * (!firsttime && !do_netmatch) || !work_valid
             *
             * ... which we can combine with what we had before:
             *
             *    p_i_p == attr_valid(attr)
             * && firsttime => work_attr == attr
             * && firsttime => policy_permit
             * && !firsttime => (Exists n :
             *                           policy_permit == route_valid(attr, n)
             *                        && work_attr == new_attr(attr, n) )
             * && do_netmatch => work_valid == (p_i_p && pfxfilter(nlri))
             * && !do_netmatch => work_valid == (p_i_p && policy_permit
             *                                             && pfxfilter(nlri))
             *
             * ----------------------------------------------------------
             * Case 1: '(!firsttime && !do_netmatch)' - this is the case where
             * we're optimising and not running policy because we already know
             * the result. In this case, we can deduce:
             *
             *    (Exists n : policy_permit == route_valid(attr, n)
             *                            && work_attr == new_attr(attr, n) )
             * && work_valid == (p_i_p && policy_permit && pfxfilter(nlri))
             *
             * which, using formula F (since !do_netmatch), gives:
             *
             *    work_attr = new_attr(attr, nlri)
             * && work_valid == p_i_p && route_valid(attr, nlri)
             *                                               && pfxfilter(nlri)
             *
             * ----------------------------------------------------------
             *
             * Case 2: '!work_valid' - this is the case where the route has
             * been marked invalid by a filter we've executed so far. It may
             * overlap with case 1 (in which case we've already shown what we
             * need to), so assume it doesn't, i.e. (firsttime || do_netmatch)
             *
             * Case 2a - do_netmatch - gives us:
             *
             *   work_valid == p_i_p && pfxfilter(nlri) == FALSE
             *
             * therefore
             *
             * p_i_p && route_valid(attr, nlri) && pfxfilter(nlri) == FALSE
             *
             * therefore work_valid == p_i_p && route_valid(attr, nlri) &&
             *                                                  pfxfilter(nlri)
             *
             * Case 2b - firsttime && !do_netmatch - gives us:
             *
             * work_valid == (p_i_p && policy_permit && pfxfilter(nlri))
             *            == FALSE
             * && policy_permit
             *
             * showing work_valid == (p_i_p && route_valid(attr, nlri) &&
             * pfxfilter(nlri)) by a similar argument to case 2a.
             *
             * ----------------------------------------------------------
             *
             * Therefore (in case 1 or 2) we have:
             *
             *    p_i_p == attr_valid(attr)
             *    work_valid == p_i_p && route_valid(attr, nlri)
             *                                               && pfxfilter(nlri)
             *    work_valid => (work_attr = new_attr(attr, nlri))
             *
             * and also the following (which haven't changed)
             *
             *    !firsttime => (Exists n :
             *                           policy_permit == route_valid(attr, n)
             *                        && work_attr == new_attr(attr, n) )
             * && firsttime => work_attr == attr
             * && firsttime => policy_permit
             */
        }

        /*
         * At this point, we've shown that:
         *
         *    p_i_p == attr_valid(attr)
         * && work_valid == p_i_p && route_valid(attr) && pfxfilter(nlri)
         *
         * i.e.
         *
         * work_valid == attr_valid(attr) && route_valid(attr, nlri)
         *                                                  && pfxfilter(nlri)
         *
         * i.e.  ** work_valid == valid(attr, nlri) **
         *
         * and also ** work_valid => (work_attr == new_attr(attr, nlri)) **
         *
         * i.e. we have the correct validity and attributes for the route :-)
         *
         * We've also shown
         *
         *    p_i_p == attr_valid(attr)
         * && firsttime => work_attr == attr
         * && firsttime => policy_permit
         * && !firsttime => (Exists n : policy_permit == valid(attr, n)
         *                               && work_attr == new_attr(attr, n) )
         *
         * ... which is the loop invariant.
         */

        if (tblattr_nlri == NULL) {
            tblattr_nlri = tblattr_entry;
        }

        /*
         * We'll never have set this because of policy.
         */
        tblattr_nlri_rcv = tblattr_entry;

        if (nexthop == NULL) {
            nexthop = nexthop_entry;
        }

        /*
         * Perform some debugging. Just a placeholder for community, it is
         * not shown - REORG
         */
        if (do_debug) {
            if (!shown_attr) {
                bgp_debug_ttyprintf(&pfx_dbg_ttys,
                                    "Received UPDATE from %s with attributes: ",
                                    bgp->neighbor_name);
                bgp_buginf_rcv_attribute(&pfx_dbg_ttys, table_ctx, attr_entry,
                                         rrinfo_entry, nexthop_entry);
                shown_attr = TRUE;
            }

            if (prefix.label != BGP_LABEL_UNASSIGNED) {
                bgp_debug_ttyprintf(&pfx_dbg_ttys,
                                    "Received prefix %s (path ID: %s) with "
                                    "MPLS label %u from neighbor %s",
                                    prefix_string, path_id_str, prefix.label,
                                    bgp->neighbor_name);
            } else {
                bgp_debug_ttyprintf(&pfx_dbg_ttys,
                                    "Received prefix %s (path ID: %s) from %s",
                                    prefix_string, path_id_str,
                                    bgp->neighbor_name);
            }

            if ((work_path->bp_flags & BPATH_VALID) == 0) {
                const char *reason = "";
                const char *name = "";

                if (!defaultpolicy_permit) {
                    reason = " due to eBGP peer with no inbound policy";
                } else if (!extcomm_permit) {
                    reason = " RT extended community is not imported locally";
                } else if (!pfxorf_permit) {
                    reason = " by prefix based ORF policy ";
                    name =
                        bgp_policy_instance_binding(bgp_af->cfg.policy_pfxorf);
                } else if (have_policy && !policy_permit) {
                    reason = " by policy ";
                    name = bgp_policy_instance_binding(bgp_af->cfg.policyin);
                }
                bgp_debug_ttyprintf(&pfx_dbg_ttys,
                                    "Prefix %s (path ID: %s) received from %s "
                                    "DENIED%s%s",
                                    prefix_string, path_id_str,
                                    bgp->neighbor_name, reason, name);
            }
        }

        /*
         * Document the reason for which the prefix was dropped
         */
        if ((work_path->bp_flags & BPATH_VALID) == 0) {
            if (!defaultpolicy_permit) {
                bgp_af->pfx_denied_no_policy++;
            } else if (!extcomm_permit) {
                bgp_af->pfx_denied_rt_permit++;
            } else if (!pfxorf_permit) {
                bgp_af->pfx_denied_orf_policy++;
            } else if (have_policy && !policy_permit) {
                bgp_af->pfx_denied_policy++;
            }
        }

        if (table_ctx->rdinfo == NULL) {
            /*
             * Based on received AFI, we derive the table context from the
             * neighbor. For the PE neighbors supporting VPNv4 unicast
             * address family, the shared table context associated with
             * BGP_AF_VPNv4 address-family doesn't point to any rdinfo.
             *
             * We need to derive the rdinfo from the RD received inside
             * vpnv4 prefix. If the path is invalid (various inbound policies
             * have rejected it), do an RD lookup so that we can treat it as
             * unreachable. Else create an rdinfo node if one doesn't exist.
             */
            if (((work_path->bp_flags & BPATH_VALID) == 0) && (!soft_reconfig)) {
                rdinfo = bgp_rdinfo_lookup(bgp_ctx, prefix.rd);

                if (rdinfo == NULL) {
                    goto next;
                }
            } else {
                rdinfo = bgp_find_or_create_rdinfo(bgp_ctx, prefix.rd, TRUE);
            }

            if (rdinfo == NULL) {
                /*
                 * Failed to find/create rdinfo node. Reset the session
                 * since this can only happen under low memory condition
                 */
                ios_msg_bgp_nomem_reset("remote rd creation");
                (void) bgp_upd_err_handle(bgp, msg, msg_size,
                                          BGP_UPD_ERR_C1_MEM_ALLOC_FAIL,
                                          0, 0, 0, NULL, 0);
                bgp_upd_err_store_reset_data(bgp,
                                             BGP_NOMEMORY,
                                             BGP_POSTIT_TYPE_NOMEMORY,
                                             BNOT_NONE, 0, NULL, 0);
                goto error_return;
            } else {

                /*
                 * This is a VPN update from a PE. But the RD node for
                 * the prefix.rd is a local RD node. So this is a same-RD
                 * import case. Set the appropriate flag to indicate that
                 * this local RD node contains remote nets.
                 */
                if (((rdinfo->rd_flags & BGP_RDINFO_FLAGS_LOCAL) != 0)
                    && BGP_TABLE_CTX_VPN(table_ctx)) {
                    rdinfo->rd_flags |= BGP_RDINFO_FLAGS_LOCAL_HAS_REMOTE_NET;
                }

                /*
                 * lock the rd info so rd won't get deleted before release
                 * the sync lock
                 */
                bgp_rdinfo_lock(rdinfo);
                need_unlock_rdinfo = TRUE;

                bgp_rdinfo_sync_unlock(rdinfo);
            }

            /*
             * This is a VPN update from a PE.  We have rdinfo.  Now
             * we need to check whether it's a remote rdinfo or local
             * rdinfo.  In case of "Same RD" we might have a rdinfo
             * pointing to a local table context.  In that case we need
             * to create tblattr inside local table_ctx instead of creating
             * inside shared table_ctx.  The original tblattr is based
             * on shared table_ctx.  So for a same RD we need a tblattr
             * based on a local table_ctx.
             */
            if (rdinfo->table_ctx != table_ctx) {
                local_table_ctx = rdinfo->table_ctx;

                if (bgp_afi_is_for_l2vpn_table(afi)) {
                    if ( ((prefix.af_size == 0) &&
                              BGP_TABLE_CTX_L2VPN_BGP(local_table_ctx)) ||
                         ((prefix.af_size > 0) &&
                              BGP_TABLE_CTX_L2VPN_LDP(local_table_ctx))) {
                        snprintf(l2vpn_pfx, sizeof(l2vpn_pfx), "%u:%u",
                                 GETSHORT(&prefix.network[0]),
                                 GETSHORT(&prefix.network[2]));
                        ios_msg_bgp_l2vpn_signal_mismatch(l2vpn_pfx,
                              bgp_address_string( BGP_AF_IPv4, (uint8_t *)&prefix.network));
                        work_path->bp_flags &= ~BPATH_VALID;
                    }
                }

                /*
                 * Create new tblattr based on local table ctx
                 */
                tblattr_temp = tblattr_nlri;
                tblattr_nlri = bgp_tblattr_find_or_insert(local_table_ctx,
                                                          tblattr_temp->attr);
                if (tblattr_nlri == NULL) {
                    ios_msg_bgp_nomem_reset("table attribute for rdinfo");
                    (void) bgp_upd_err_handle(bgp, msg, msg_size,
                                              BGP_UPD_ERR_C1_MEM_ALLOC_FAIL,
                                              0, 0, 0, NULL, 0);
                    bgp_upd_err_store_reset_data(bgp,
                                                 BGP_NOMEMORY,
                                                 BGP_POSTIT_TYPE_NOMEMORY,
                                                 BNOT_NONE, 0, NULL, 0);
                    goto error_return;
                }

                if (soft_reconfig) {
                    /*
                     * Soft reconfig tblattr
                     */
                    if (tblattr_temp == tblattr_nlri_rcv) {
                        /*
                         * The "received" and "used" tblattr for this NLRI
                         * are the same, so we can just use the local table
                         * tblattr computed above as the "received"
                         * tblattr
                         */
                        tblattr_nlri_rcv = tblattr_nlri;
                    } else {
                        /*
                         * We don't need to worry about caching the old
                         * pointer value since there will always be another
                         * pointer to that same tblattr struct.
                         */
                        tblattr_nlri_rcv =
                            bgp_tblattr_find_or_insert(local_table_ctx,
                                                       tblattr_nlri_rcv->attr);
                        if (tblattr_nlri_rcv == NULL) {
                            ios_msg_bgp_nomem_reset("received table attribute");
                            (void) bgp_upd_err_handle(bgp, msg, msg_size,
                                                 BGP_UPD_ERR_C1_MEM_ALLOC_FAIL,
                                                 0, 0, 0, NULL, 0);
                            bgp_upd_err_store_reset_data(bgp,
                                                 BGP_NOMEMORY,
                                                 BGP_POSTIT_TYPE_NOMEMORY,
                                                 BNOT_NONE, 0, NULL, 0);
                            goto error_return;
                        }
                    }
                }
            }
        } else {
            rdinfo = BGP_TABLE_CTX_TO_RDINFO(table_ctx);
        }

        if (bgp_rdinfo_not_on_bump_list(rdinfo,
                                        BGP_RDINFO_BUMP_FLAG_RTR_THREAD)) {
            bgp_rdinfo_add_to_bump_list(&bgpinfo_rtr_rdinfo_bump_list,
                                        BGP_RDINFO_BUMP_FLAG_RTR_THREAD,
                                        rdinfo);
        }

        /*
         * We can unlock the rdinfo here since it will not have chance
         * to get deleted (it is on the bump list already)
         */
        if (need_unlock_rdinfo) {
            need_unlock_rdinfo = FALSE;
            bgp_rdinfo_unlock(rdinfo);
        }

        /*
         * We are ready to accept the route. Based on what we read
         * from the wire, update the work_path with the received
         * label. If we didn't receive any label with the path, the
         * prefix will point to BGP_LABEL_UNASSIGNED
         */
        work_path->rcvd_label = prefix.label;

        /*
         * Update the msgin_pathptr->rcvd_label as well since that is the
         * one used in case of soft_reconfig to add the denied path. It
         * should have the correct label.
         */
        msgin_pathptr->rcvd_label = prefix.label;

        work_path->peer_path_id = prefix.path_id;
        msgin_pathptr->peer_path_id = prefix.path_id;

        /*
         * AF dependent routine to transfer AF data from the prefix to
         * the path structure.
         */
        bgp_prepare_path(table_ctx, &prefix, work_path, NULL);

        /*
         * SYNC: We get a locked net from bgp_lookup_prefix or
         * bgp_create_net_pfx and release the lock latter when we are done
         * processing it.
         */
        net = bgp_lookup_prefix(table_ctx, rdinfo, &prefix);
        /*
         * Sanity checks against mixing the signalling types
         */
        if (bgp_afi_is_for_l2vpn_table(afi) && net) {
            if ( ((prefix.af_size == 0) && BNET_IS_BGP_SIGNALLED(net)) ||
                 ((prefix.af_size > 0) && BNET_IS_LDP_SIGNALLED(net)) ) {
                snprintf(l2vpn_pfx, sizeof(l2vpn_pfx), "%u:%u",
                                        GETSHORT(net->network),
                                        GETSHORT(&net->network[2]));
                ios_msg_bgp_l2vpn_signal_overlap(l2vpn_pfx,
                            bgp_address_string( BGP_AF_IPv4, net->network));
                bnet_sync_unlock(net);
                work_path->bp_flags &= ~BPATH_VALID;
                //goto error_return;
            }
        }

        /*
         * Create the net if not present only when the new path learnt is
         * valid OR we are running with soft reconfig enabled.
         */
        if (!net) {
            if ((work_path->bp_flags & BPATH_VALID) != 0 || soft_reconfig) {
                /*
                 * In the case when same RD update arrives from a PE peer,
                 * we need to use the local table_ctx instead of a shared
                 * table context.  Always use the table_ctx from the rdinfo
                 * while creating the net.  That way correct PE/CE bitfields
                 * get assigned to the net.
                 */
                net = bgp_create_net_pfx(rdinfo->table_ctx, rdinfo,
                                         prefix.network, prefix.masklen);
                if (!net) {
                    ios_msg_bgp_nomem_reset("net");
                    (void) bgp_upd_err_handle(bgp, msg, msg_size,
                                              BGP_UPD_ERR_C1_MEM_ALLOC_FAIL,
                                              0, 0, 0, NULL, 0);
                    bgp_upd_err_store_reset_data(bgp,
                                                 BGP_NOMEMORY,
                                                 BGP_POSTIT_TYPE_NOMEMORY,
                                                 BNOT_NONE, 0, NULL, 0);
                    goto error_return;
                }
                if (bgp_afi_is_for_l2vpn_table(afi)) {
                    if (prefix.af_size == 0) {
                        net->extflags |= BNET2_LDP_SIGNALLED;
                    } else {
                        net->extflags |= BNET2_BGP_SIGNALLED;
                    }
                }
            } else {
                bgp_af->pfx_denied++;
                goto next;
            }
        }

        if (soft_reconfig) {

            /*
             * Find the current path, and update the received prefix count
             * for this neighbor (if necessary).
             */
            path = bgp_find_usedpath(table_ctx, net, bgp, prefix.path_id,
                                     &do_bestpath,
                                     ((work_path->bp_flags & BPATH_VALID) != 0));
        } else {
            path = bgp_find_rcvd_path(net, &(bgp->nbrinfo), prefix.path_id);

            if (path != NULL) {
                /*
                 * There is a path to be removed/replaced by the new path,
                 * so update the received prefix count.
                 */
                bgp_rcvd_prefix_decr(bgp, table_ctx, net, path);
            }
        }

        if ((work_path->bp_flags & BPATH_VALID) != 0) {

            if (path) {

                /*
                 * Path present in the BGP table. Update it.
                 */
                if (bgp4_update_existing_path(table_ctx, bgp, net, work_path,
                                              path, tblattr_nlri, &duplicate,
                                              &tblattr_best, &old_nexthop,
                                              rrinfo_entry, nexthop)) {
                    /*
                     * Update the prefix count for the neighbor to reflect
                     * the presence of the new path.
                     */
                    bgp_rcvd_prefix_incr(bgp, table_ctx, path);
                    
                    bgp_af_nbr_upd_prep(table_ctx, 
                                        bgp, 
                                        net, work_path, TRUE, TRUE, 
                                        FALSE, FALSE);
                    path->bp_flags &= ~BPATH_STALE;

                    /*
                     * Clear the stale flag for a rcvd-only path
                     * on re-advertisement of the update for used path
                     * to prevent purging of the same after eor is received
                     * or with stalepath timer expiry.
                     */
                    if ((BGP_PATH_NEXT_IS_SOFT(path)) &&
                        ((path->next->bp_flags & BPATH_RCVD_ONLY) != 0)) {

                        path->next->bp_flags &= ~BPATH_STALE;
                    }

                    if (!duplicate) {
                        do_bestpath = TRUE;
                    }
                } else {
                    (void) bgp_upd_err_handle(bgp, msg, msg_size,
                                              BGP_UPD_ERR_C1_MEM_ALLOC_FAIL,
                                              0, 0, 0, NULL, 0);
                    bgp_upd_err_store_reset_data(bgp,
                                                 BGP_NOMEMORY,
                                                 BGP_POSTIT_TYPE_NOMEMORY,
                                                 BNOT_NONE, 0, NULL, 0);
                    goto error_return;
                }
            } else {
                /*
                 * Path absent in the BGP table. Add a new one.
                 */
                path = bgp_add_path(table_ctx, net, work_path, NULL, NULL,
                                    tblattr_nlri, rrinfo_entry, nexthop,
                                    bgp_nbrinfo(bgp), NULL, TRUE, TRUE, FALSE, FALSE);

                if (!path) {
                    ios_msg_bgp_nomem_reset("path");
                    bnet_sync_unlock(net);
                    (void) bgp_upd_err_handle(bgp, msg, msg_size,
                                              BGP_UPD_ERR_C1_MEM_ALLOC_FAIL,
                                              0, 0, 0, NULL, 0);
                    bgp_upd_err_store_reset_data(bgp,
                                                 BGP_NOMEMORY,
                                                 BGP_POSTIT_TYPE_NOMEMORY,
                                                 BNOT_NONE, 0, NULL, 0);
                    goto error_return;
                }

                /*
                 * Update the prefix count for the neighbor to reflect
                 * the presence of the new path.
                 */
                bgp_rcvd_prefix_incr(bgp, table_ctx, path);
                tblattr_best = bgp_bestpath_attr(net, &old_nexthop);
                bgp_tblattr_lock(tblattr_best);
                bgp_nexthop_lock(old_nexthop, NULL);
                do_bestpath = TRUE;
            }

            /*
             * Prevent a race condition here.  While we've decided to not
             * perform a best path computation, some other thread may have
             * updated the next hop information.  If updating the path
             * metric changes anything, we should re-evaluate the best
             * path.
             */
            oldmetric = path->gwmetric;
            bgp_set_path_metric(net, path);
            if (oldmetric != path->gwmetric) {
                do_bestpath = TRUE;
            }
        } else {
            if (path) {
                /*
                 * New path is invalid. Delete the existing path in the table.
                 * Note that the received prefix count has already been
                 * updated to reflect the removal of this path.
                 */
                tblattr_best = bgp_bestpath_attr(net, &old_nexthop);
                bgp_tblattr_lock(tblattr_best);
                bgp_nexthop_lock(old_nexthop, NULL);
                if (SPEAKER_DO_GROUP_BESTPATH(net, path)) {
                    do_bestpath = TRUE;
                }
                bgp_delete_path(table_ctx, net, &path, TRUE, FALSE, FALSE);
            }

            bgp_af->pfx_denied++;
        }

        /*
         * Now that we might have accepted new path, verify if we have
         * exceeded the limit.
         */
        if (bgp_rcv_pfx_over_limit(table_ctx, bgp_af)) {
            bnet_sync_unlock(net);

            /*
             * Send out a CEASE notification and reset the neighbor
             */
            bgp_max_prefix_exceeded(afi, bgp);
            goto error_return;
        }

        /*
         * We now need to check if soft reconfig inbound is configured and
         * insert the denied path.
         */
        if (soft_reconfig) {
            if (!bgp_add_or_update_denied_path(table_ctx, bgp, net, path,
                                               msgin_pathptr, tblattr_nlri_rcv,
                                               attr_changed, rrinfo_entry,
                                               nexthop_entry, &prefix)) {
                ios_msg_bgp_nomem_reset("RCVD_ONLY path");
                bnet_sync_unlock(net);
                (void) bgp_upd_err_handle(bgp, msg, msg_size,
                                          BGP_UPD_ERR_C1_MEM_ALLOC_FAIL,
                                          0, 0, 0, NULL, 0);
                bgp_upd_err_store_reset_data(bgp,
                                             BGP_NOMEMORY,
                                             BGP_POSTIT_TYPE_NOMEMORY,
                                             BNOT_NONE, 0, NULL, 0);
                goto error_return;
            }
        }

        if (do_bestpath) {
            /* sa_ignore NO_NULL_CHK */
            bgp_bestpath(rdinfo->table_ctx, net, path, tblattr_best,
                         old_nexthop,
                         BNET_NEED_RIB_PROCESSING + BNET_NEED_UPD_PROCESSING +
                         BNET_NEED_IMP_PROCESSING + BNET_NEED_BRIB_PROCESSING);
        }

        /*
         * We are done with this net... unlock it.
         */
        bgp_tblattr_unlock(table_ctx, tblattr_best);
        bgp_nexthop_unlock(old_nexthop, NULL);
        tblattr_best = NULL;
        old_nexthop = NULL;

        do_import_ao =
            (do_bestpath &&
             bgp_afi_is_for_vpn_table(afi) &&
             ((msgin_attr->flags & BATTR_AO) != 0) &&
             ((msgin_pathptr->bp_flags & BPATH_AO_SO) != 0) &&
             ((net->rdinfo->rd_flags & BGP_RDINFO_FLAGS_LOCAL) != 0));

        if (do_import_ao) {
            /* Incr net refcnt before net unlock. Need to do net
               unlock so that net ver gets bumped. The AO import logic
               requires an updated net ver. */
            bnet_lock(net);
            bnet_sync_unlock(net);

            /* Send net to import thread for import processing. */
            bgp_import_c_net_ao(net);

            bnet_unlock(net);
        } else {
            bnet_sync_unlock(net);
        }

    next:
        if (tblattr_temp != NULL) {

            if (soft_reconfig &&
                tblattr_nlri_rcv != NULL &&
                tblattr_nlri_rcv != tblattr_entry &&
                tblattr_nlri_rcv != tblattr_nlri) {
                /*
                 * We did a find/insert for a rcv-only same-RD tblattr.
                 * Clear it up.
                 */
                bgp_tblattr_unlock(local_table_ctx, tblattr_nlri_rcv);
            }


            /*
             * At this point we have cached original tblattr_nlri into
             * tblattr_temp.  tblattr_nlri is crrently pointing to the new
             * tblattr associated with the same RD local table context.
             * Unlock the local table tblattr_nlri and restore the
             * original tblattr_nlri.
             */
            bgp_tblattr_unlock(local_table_ctx, tblattr_nlri);
            tblattr_nlri = tblattr_temp;
            tblattr_temp = NULL;
        }

        if (do_netmatch) {
            if (tblattr_nlri != tblattr_entry) {
                bgp_tblattr_unlock(table_ctx, tblattr_nlri);
                tblattr_nlri = NULL;
            }
            if (nexthop != nexthop_entry) {
                bgp_nexthop_unlock(nexthop, table_ctx);
                nexthop = NULL;
            }
        }
    }

    /*
     * Policy is evaluated for the first prefix only;
     * Time to unlock it.
     */
    bgp_policy_config_group1_unlock();

    if (!do_netmatch) {
        if (tblattr_nlri != tblattr_entry) {
            bgp_tblattr_unlock(table_ctx, tblattr_nlri);
        }
        if (nexthop != nexthop_entry) {
            bgp_nexthop_unlock(nexthop, NULL);
        }
    }

    if (rrinfo_entry) {
        bgp_attrinfo_unlock(rrinfo_entry, BGP4_PROCESS_REACHABLES_1I);
    }
    bgp_nexthop_unlock(nexthop_entry, NULL);
    bgp_tblattr_unlock(table_ctx, tblattr_entry);

    return;

error_return:
    if (need_unlock_rdinfo && rdinfo) {
        bgp_rdinfo_unlock(rdinfo);
    }
    if (policy_lock == TRUE) {
        bgp_policy_config_group1_unlock();
    }
    if (rrinfo_entry) {
        bgp_attrinfo_unlock(rrinfo_entry, BGP4_PROCESS_REACHABLES_2I);
    }
    if (nexthop != nexthop_entry) {
        bgp_nexthop_unlock(nexthop, NULL);
    }
    bgp_nexthop_unlock(nexthop_entry, NULL);

    if (tblattr_nlri != NULL && tblattr_nlri != tblattr_entry) {
        bgp_tblattr_unlock(table_ctx, tblattr_nlri);
    }
    bgp_tblattr_unlock(table_ctx, tblattr_entry);
    bgp_tblattr_unlock(table_ctx, tblattr_best);
    bgp_nexthop_unlock(old_nexthop, NULL);

    return;
}


static bool
bgp4_rcv_ipv4_unicast_eor (uchar_t         *data,
                           bgp_nbrtype     *nbr,
                           bgp_dbg_ttylist *error_ttylist)
{
    if ((GETSHORT(data) == 0) &&
        (GETSHORT((data + sizeof(ushort_t))) == 0)) {

        bgp_debug_ttyprintf(error_ttylist, "EoR received from %s",
                            nbr->neighbor_name);
        bgp_process_eor(nbr, BGP_AF_IPv4, TRUE);
        return (TRUE);
    } else {
        return (FALSE);
    }
}


/*
 * edt: * * bgp4_rcv_update
 *
 * Handle a received UPDATE message from a BGP4 peer
 *
 * Return: bool
 *         TRUE if UPDATE message has prefixes that we are interested in.
 *         (i.e. there exists ttys have requested debug messages related to
 *          prefixes contained in UPDATE message)
 *
 * Argument: bgp_nbrtype *bgp
 *   IN    - Neighbor Structure
 *
 * Argument: uchar_t *data
 *   IN    - Data of Update message to read
 *
 * Argument: uint16_t bytes
 *   IN    - Bytes of message to read
 *
 * Argument: bgp_dbg_ttylist *error_ttylist
 *   IN    - Debug ttylist to use for displaying debugs when errors are
 *           encountered during the processing of the update.
 *
 * Argument: bool debug
 *   IN    - Turn on debugging
 */
static bool
bgp4_rcv_update (bgp_nbrtype     *nbr,
                 uint8_t         *msg,
                 uint16_t         len,
                 bmsgtype        *bmsg)
{
    uint8_t                 afi = BGP_AF_NONE;
    uint8_t                *data = NULL;
    uint16_t                bytes = 0;
    uint8_t                *upd_data = NULL;
    uint16_t                upd_len = 0;
    uint8_t                *ipv4_wdr_data = NULL;
    uint16_t                ipv4_wdr_len = 0;
    uint8_t                *attr_block_data = NULL;
    uint16_t                attr_block_len = 0;
    uint8_t                *ipv4_reach_data = NULL;
    uint16_t                ipv4_reach_len = 0;
    uint8_t                 path_buf[bgp_info.max_path_size];
    bpathtype              *msgin_pathptr = NULL;
    battrtype               msgin_attr;
    uint32_t                battr_aigp_flag = 0;
    bgp_tblattrtype         msgin_tblattr;
    bnlritype              *bgp_nlri = NULL;
    bgp_tblctxtype         *table_ctx = NULL;
    bgp_afnbrtype          *nbr_af = NULL;
    bool                    same_cluster = FALSE;
    uint8_t                 myas_count = 0;
    uint32_t                attr_wdr_flags = 0;
    uint32_t                nlri_attr_wdr_flags = 0;
    uint8_t                 nlri_attr_code = 0;
    uint32_t                nlri_err_flag = 0;
    uint8_t                 filter_action = BGP_UPD_FILTER_ACTION_NONE;
    bgp_upd_err_action_t    err_action = BGP_UPD_ERR_ACTION_NONE;
    bool                    reach_nlri_withdrawn = FALSE;
    bool                    net_debug_match = FALSE;
    bool                    nexthop_cleanup_needed;



    if (len < BGP_HEADERBYTES) {

        // TODO: the length declared in the BGP header is crazy. make some noise

        goto free_and_return;
    }

    /*
     * Set the Update data and bytes to read
     */
    data = msg + BGP_HEADERBYTES;
    bytes = len - BGP_HEADERBYTES;

    upd_data = data;
    upd_len = bytes;

    /*
     * If IPv4 unicast AF is enabled on the neighbor, check if this update
     * message is EoR for IPv4 unicast.
     */
    if (BGP_NBR_AF_NEGOTIATED(nbr->af[BGP_AF_IPv4])) {
        if (bgp4_rcv_ipv4_unicast_eor(data, nbr, error_ttylist)) {
            // Process any errors encountered during processing of this update
            bgp_upd_err_ctx_msg_finish(nbr);

            // No need to do anything w.r.t. update filtering here...

            return (FALSE);
        }
    }

    //========================================================================
    /*
     * Parse the IPv4 Withdrawn Routes block
     */
    // IPv4 Withdrawn Routes Length
    if (bytes < sizeof(uint16_t)) {
        
        // TODO: bytes remaining is crazy small. make some noise

        goto free_and_return;
    }

    ipv4_wdr_len = GETSHORT(data);

    data += sizeof(uint16_t);
    bytes -= sizeof(uint16_t);

    // IPv4 Withdrawn Routes NLRIs
    if (bytes < ipv4_wdr_len) {
        BGP_DEBUG_UPD_IN(BGP_AF_NONE, NULL, bgp_nbr_addr(nbr),
                         B_DIR_IN, NULL, 0,
                         BGP_OPT_DFLT, BGP_DBG_LEVEL_WARNING,
                         "Malformed update from %s: IPv4 WdrRoutes len %u "
                         "is more than remaining msg len %u",
                         nbr->neighbor_name,
                         ipv4_wdr_len, bytes);


        goto free_and_return;
    }

    ipv4_wdr_data = data;

    data += ipv4_wdr_len;
    bytes -= ipv4_wdr_len;

    //========================================================================
    /*
     * Parse the Attributes block
     */
    // Attributes Length field
    if (bytes < sizeof(uint16_t)) {
        err_action = bgp_upd_err_handle(nbr, msg, len,
                                        BGP_UPD_ERR_C1_MSG_LEN_INCONST,
                                        0, 0, 0,
                                        upd_data, sizeof(uint16_t));
        goto free_and_return;
    }

    attr_block_len = GETSHORT(data);

    data += sizeof(uint16_t);
    bytes -= sizeof(uint16_t);

    // Attributes
    if (bytes < attr_block_len) {
        BGP_DEBUG_UPD_IN(BGP_AF_NONE, NULL, bgp_nbr_addr(nbr),
                         B_DIR_IN, NULL, 0,
                         BGP_OPT_DFLT, BGP_DBG_LEVEL_WARNING,
                         "Malformed update from %s: Attributes block len %u "
                         "is more than remaining msg len %u",
                         nbr->neighbor_name,
                         attr_block_len, bytes);
        BGP_TRACE(BGP_TP_20,
                  nbr->neighbor_name, "Attributes block",
                  attr_block_len, bytes);

        err_action = bgp_upd_err_handle(nbr, msg, len,
                                        BGP_UPD_ERR_C1_MSG_LEN_INCONST,
                                        0, 0, 0,
                                        (data - sizeof(uint16_t)),
                                        sizeof(uint16_t));
        bgp_upd_err_store_reset_data(nbr,
                                     BGP_NONE, BGP_POSTIT_TYPE_UPDATE_MALFORMED,
                                     BNOT_UPDATE, BNOT_UPDATE_MALFORMED,
                                     (data - sizeof(uint16_t)),
                                     sizeof(uint16_t));

        goto free_and_return;
    }

    attr_block_data = data;

    data += attr_block_len;
    bytes -= attr_block_len;

    //========================================================================
    /*
     * Parse the IPv4 NLRI block
     */
    ipv4_reach_data = data;
    ipv4_reach_len = bytes;

    //========================================================================

    //========================================================================
    /*
     * Parse IPv4 Withdrawn Routes NLRIs
     */
    bgp4_rcv_v4withdrawn(nbr, msg, len,
                         ipv4_wdr_data, ipv4_wdr_len,
                         error_ttylist);

    err_action = bgp_upd_err_get_final_action(nbr);
    if (BGP_UPD_ERR_ACTION_STOP_MSG(err_action)) {
        goto free_and_return;
    }

    //========================================================================
    /*
     * Parse Attributes
     */
    bgp4_rcv_buffer_init(nbr, msgin_pathptr, &msgin_tblattr);

    bgp4_rcv_attributes(nbr, msg, len,
                        upd_len,
                        attr_block_data, attr_block_len,
                        ipv4_reach_len,
                        bmsg, msgin_pathptr, &same_cluster,
                        ((nbr->flags & BN_ALLOWAS_IN) ? &myas_count : NULL),
                        TRUE, &attr_wdr_flags,
                        error_ttylist);

    err_action = bgp_upd_err_get_final_action(nbr);
    if (BGP_UPD_ERR_ACTION_STOP_MSG(err_action)) {
        nexthop_cleanup_needed = TRUE;
        goto free_and_return;
    }

    //========================================================================
    /*
     * Parse IPv4 Routes NLRIs
     */
    bgp4_rcv_v4prefixes(nbr, msg, len,
                        attr_block_len, 
                        ipv4_reach_data, ipv4_reach_len,
                        msgin_pathptr,
                        error_ttylist);

    err_action = bgp_upd_err_get_final_action(nbr);
    if (BGP_UPD_ERR_ACTION_STOP_MSG(err_action)) {
        nexthop_cleanup_needed = TRUE;
        goto free_and_return;
    }

    //========================================================================
    /*
     * Validate Attributes
     */
    // If filtering or error action indicates that NLRIs have to be withdrawn,
    // then there is no need to do validation of received attributes.
    filter_action = bgp_upd_filter_get_final_action(nbr);
    err_action = bgp_upd_err_get_final_action(nbr);

    if ((filter_action != BGP_UPD_FILTER_ACTION_WDR) &&
        (err_action != BGP_UPD_ERR_ACTION_WDR) &&
        (err_action != BGP_UPD_ERR_ACTION_WDR_OR_RESET)) {

        bgp4_validate_attributes(nbr, msg, len,
                                 attr_block_len, 
                                 msgin_pathptr, same_cluster,
                                 &attr_wdr_flags, error_ttylist);
    }

    err_action = bgp_upd_err_get_final_action(nbr);
    if (BGP_UPD_ERR_ACTION_STOP_MSG(err_action)) {
        nexthop_cleanup_needed = TRUE;
        goto free_and_return;
    }

    //========================================================================
    /*
     * Process the received UNREACHABLE and REACHABLE NLRIs. The NEXT_HOP
     * is stored in msg_pathptr for IPv4, and in bgp_nlri for MP_REACH.
     * We need to preserve the one in msg_pathptr after processing.
     */

    // Set up accept-own self-originated path flag
    if (((msgin_pathptr->bp_flags & BPATH_AO) != 0) &&
        ((attr_wdr_flags & (BGP_UPD_WDR_ORIGINATOR_OWN |
                            BGP_UPD_WDR_NH_LOCAL |
                            BGP_UPD_WDR_MP_NH_LOCAL)) != 0)) {
        msgin_pathptr->bp_flags |= BPATH_AO_SO;
    }


    // Save the original AIGP attr flag
    battr_aigp_flag = (msgin_attr.flags & BATTR_AIGP);

    // Make sure we can dump an 'useless' update msg
    if (queue_empty(&bgpinfo_nlriQ)) {
        net_debug_match = TRUE;
    }

    // Read the final filtering action so far
    filter_action = bgp_upd_filter_get_final_action(nbr);

    while (!queue_empty(&bgpinfo_nlriQ)) {

        // Initialize some AFI specific variables
        afi = BGP_AF_NONE;
        table_ctx = NULL;
        nbr_af = NULL;
        nlri_attr_wdr_flags = 0;
        nlri_attr_code = 0;
        nlri_err_flag = 0;

        //======== NLRI validations below this =============================

        // Check for any fatal errors so far
        err_action = bgp_upd_err_get_final_action(nbr);
        if (BGP_UPD_ERR_ACTION_STOP_MSG(err_action)) {
            nexthop_cleanup_needed = TRUE;
            goto free_and_return;
        }

        // Read NLRI block
        bgp_nlri = queue_dequeue(&bgpinfo_nlriQ);
        if (bgp_nlri == NULL) {
            continue;
        }

        afi = bgp_nlri->afi;

        if (afi < BGP_AF_MAX) {
            table_ctx = BGP_NBR_TO_TABLE_CTX(nbr, afi);
            nbr_af = nbr->af[afi];
        }

        // Check if this AFI is configured and negotiated
        if ((!bgp4_rcv_afi_is_acceptable(nbr, BGP_TYPE_UPDATE,
                                         afi,
                                         bgp_nlri->rcvd_afi,
                                         bgp_nlri->rcvd_safi,
                                        "NLRI block", error_ttylist)) ||
            (table_ctx == NULL) ||
            (nbr_af == NULL)) {

            bnlri_free(bgp_nlri);
            bgp_nlri = NULL;
            net_debug_match = TRUE;
            continue;
        }

        //======== NLRI validations above this =============================

        // Set AIGP attr flag based on AIGP config for this nbr-af
        if ((nbr_af->af2_flags & BN_AF2_AIGP) != 0) {
            msgin_attr.flags |= battr_aigp_flag;
        } else {
            msgin_attr.flags &= ~BATTR_AIGP;
        }

        // Make a copy of the original WDR flags
        nlri_attr_wdr_flags = attr_wdr_flags;

        // For MP NLRIs, clear the non-MP WDR flags and vice-versa
        if ((bgp_nlri->flags & BNLRI_MP) != 0) {
            nlri_attr_wdr_flags &= ~BGP_UPD_WDR_NON_MP;
        } else {
            nlri_attr_wdr_flags &= ~BGP_UPD_WDR_MP;
        }

        // Clear self-originate attr errs if accept-own community
        // present. VPN-only.
        if (((msgin_attr.flags & BATTR_AO) != 0) &&
            (bgp_afi_is_for_vpn_table(afi))) {

            if ((nbr_af->af2_flags & BN_AF2_AO) != 0) {
                nlri_attr_wdr_flags &= ~(BGP_UPD_WDR_ORIGINATOR_OWN |
                                         BGP_UPD_WDR_NH_LOCAL |
                                         BGP_UPD_WDR_MP_NH_LOCAL);
            }
        }

        // Check as-path loop for each NLRI type.
        if (nbr->flags & BN_ALLOWAS_IN) {
            if (nbr_af->af_flags & BN_AF_ALLOWAS_IN) {
                /*
                 * If allow-as flag is set for the AFI, and my AS count
                 * in AS path is greater than the configured AS count,
                 * flag error.
                 */
                if (myas_count > nbr_af->cfg.allowas_in_count) {
                    nlri_attr_wdr_flags |= BGP_UPD_WDR_ASPATH_LOOP;
                }
            } else if (myas_count > 0) {
                /*
                 * If allow-as flag is not set for the AFI, and my AS count
                 * is non zero, then bgp_asloop_detect would FAIL, and
                 * BGP_UPD_WDR_ASPATH_LOOP flag will not be set, so flag
                 * error here.
                 */
                nlri_attr_wdr_flags |= BGP_UPD_WDR_ASPATH_LOOP;
            }
        }

        // Set the path weight for this nbr-af
        msgin_pathptr->weight = nbr_af->cfg.weight;

        // Set the attr code and potential update error flag
        if ((bgp_nlri->flags & BNLRI_MP) != 0) {
            if (bgp_nlri->code == BGP_REACHABLE_NLRI) {
                nlri_attr_code = ATT4_MP_REACH_NLRI;
                nlri_err_flag = BGP_UPD_ERR_C1_MP_REACH_NLRI;
            } else {
                nlri_attr_code = ATT4_MP_UNREACH_NLRI;
                nlri_err_flag = BGP_UPD_ERR_C1_MP_UNREACH_NLRI;
            }
        } else {
            if (bgp_nlri->code == BGP_REACHABLE_NLRI) {
                nlri_err_flag = BGP_UPD_ERR_C1_IPV4_NLRI;
            } else {
                nlri_err_flag = BGP_UPD_ERR_C1_IPV4_WDR;
            }
        }

        // Process each NLRI block as reachable or unreachable
        if (bgp_nlri->code == BGP_REACHABLE_NLRI) {
            msgin_pathptr->nexthop = bgp_nlri->nexthop;

            if ((nlri_attr_wdr_flags != 0) ||
                (filter_action == BGP_UPD_FILTER_ACTION_WDR) ||
                (err_action == BGP_UPD_ERR_ACTION_WDR) ||
                (err_action == BGP_UPD_ERR_ACTION_WDR_OR_RESET)) {

                reach_nlri_withdrawn = TRUE;

                bgp4_process_unreachables(nbr,
                                          msg, len, 
                                          bgp_nlri, msgin_pathptr,
                                          nlri_attr_wdr_flags,
                                          nlri_attr_code, nlri_err_flag,
                                          filter_action, err_action,
                                          debug, &net_debug_match);
                nexthop_cleanup_needed = TRUE;
            } else {
                bgp4_process_reachables(nbr,
                                        msg, len,
                                        bgp_nlri, msgin_pathptr,
                                        nlri_attr_code, nlri_err_flag,
                                        filter_action, err_action,
                                        debug, &net_debug_match);
            }
        } else {
            bgp4_process_unreachables(nbr,
                                      msg, len, 
                                      bgp_nlri, NULL,
                                      nlri_attr_wdr_flags,
                                      nlri_attr_code, nlri_err_flag,
                                      filter_action, err_action,
                                      debug, &net_debug_match);
        }

        // Free NLRI
        bnlri_free(bgp_nlri);
        bgp_nlri = NULL;
    }

free_and_return:
    /*
     * Check if we need to update the final action
     */
    filter_action = bgp_upd_filter_get_final_action(nbr);

    err_action = bgp_upd_err_get_final_action(nbr);

    if (err_action == BGP_UPD_ERR_ACTION_WDR_OR_RESET) {
        if (reach_nlri_withdrawn) {
            bgp_upd_err_set_final_action(nbr, BGP_UPD_ERR_ACTION_WDR);
        } else {
            bgp_upd_err_set_final_action(nbr, BGP_UPD_ERR_ACTION_RESET);
        }
    }

    if ((filter_action != BGP_UPD_FILTER_ACTION_NONE) ||
        (err_action != BGP_UPD_ERR_ACTION_NONE)) {
        net_debug_match = TRUE;
    }

    /*
     * Cleanup any leftover NLRIs and attributes
     */
    while (!queue_empty(&bgpinfo_nlriQ)) {
        bgp_nlri = queue_dequeue(&bgpinfo_nlriQ);
        bnlri_free(bgp_nlri);
        bgp_nlri = NULL;
    }

    if (msgin_attr.transptr) {
        free(msgin_attr.transptr);
        msgin_attr.transptr = NULL;
    }

    /*
     * Complete error-handling and filtering for this update message.
     * This will do things like printing ios_msg, starting nbr reset, etc.
     */
    bgp_upd_filter_ctx_msg_finish(nbr);
    bgp_upd_err_ctx_msg_finish(nbr);

    /*
     * When a nexthop is created and stored in context of msgin_pathptr
     * (bgp4_rcv_nexthop) the nexthop lock increments the refcount of 
     * the nexthop in bgp_find_or_create_nexthop(). 
     * On hitting error cases as above in 
     * bgp4_rcv_update, the usage refcount of the nexthop needs to be 
     * to be decremented by one as it's reference it msgin_pathptr is no
     * longer relevant.
     */
    if (nexthop_cleanup_needed && (msgin_pathptr->nexthop != NULL) &&
        (msgin_pathptr->nexthop != bgprtr_msg_nexthopbuf)) {
        bgp_nexthop_unlock(msgin_pathptr->nexthop, NULL);
    }

    return (net_debug_match);
}


/*
 * edt: * * bgp_docommand
 *
 * Read and process messages from a BGP neighbor
 *
 * Return: int
 *   Number of messages read from the readQ
 *
 * Argument: nbr
 *   IN    - The neighbor to process
 *
 * Argument: read_suspended
 *   OUT   - This is set to TRUE if reached the message limit and did
 *           not empty the queue.
 *
 * Argument: msglimit
 *   IN    - Maximum number of message to read
 */
static int
bgp_docommand (bgp_nbrtype *nbr,
               bool        *read_suspended,
               int          msglimit)
{
    bmsgtype        *msg;                   /* Message read from queue       */
    bgp_header      *header;                /* Message header                */
    uint16_t         bytes;                 /* Length of message             */
    bgp_dbg_ttylist  debug_update_list;     /* TTYs for debug output         */
    bool             debugging_updates;     /* Whether to do debugging       */
    int              count = 0;             /* Number of message read        */
    bool             read_more_msgs = TRUE; /* Stop when FALSE               */
    bgp_time         elapsed;               /* Time taken                    */
    bgp_ts           tm;                    /* Timestamp for time taken      */
    bgp_vrfctxtype  *vrf_ctx;               /* VRF context                   */
    bgp_afnbrtype   *nbr_af;
    uint32_t         initial_delta_rt_set_size = 0;

    bgp_get_timestamp(&tm);
    nbr_af = nbr->af[BGP_AF_RT_CONSTRAINT];
    if (!BGP_NBR_AF_DELETED(nbr_af)) {
        initial_delta_rt_set_size = nbr_af->delta_rt_set.size;
    }

    while (read_more_msgs && atomic_read(&nbr->bgp_state) != BGPS_CLOSING) {
        if (count >= msglimit) {
            *read_suspended = TRUE;
            read_more_msgs = FALSE;
            msg = NULL;
        } else {
            read_more_msgs = bgp_sync_nbr_read_check(nbr);
            if (read_more_msgs) {
                BGP_MUTEX_LOCK(&bgpinfo_netqueue_mutex);
                msg = queue_dequeue(&nbr->readQ.queue);
                if (msg == NULL) {
                    read_more_msgs = FALSE;
                } else if (queue_empty(&nbr->readQ.queue)) {
                    /*sa_ignore NO_NULL_CHK*/
                    *nbr->readQ.prev_readq_ptr = nbr->readQ.next_readq_nbr;
                    if (nbr->readQ.next_readq_nbr != NULL) {
                        nbr->readQ.next_readq_nbr->readQ.prev_readq_ptr =
                            nbr->readQ.prev_readq_ptr;
                    }
                    nbr->readQ.next_readq_nbr = NULL;
                    nbr->readQ.prev_readq_ptr = NULL;
                    atomic_sub(&bgpinfo_netqueue_nbr_count, 1);
                }
                BGP_MUTEX_UNLOCK(&bgpinfo_netqueue_mutex);
            } else {
                msg = NULL;
            }
        }

        if (read_more_msgs) {
            count++;
            nbr->msg_stats.total.rx.cnt++;
            header = (bgp_header *) msg->datagramstart;

            /*
             * Get byte count (already range checked)
             */
            bytes = GETSHORT(header->len);

            /*
             * There should only be update messages on the queue.
             */
            if (header->type != BGP_TYPE_UPDATE) {
                ios_msg_bgp_internal_error("non-update msg in router thread");
                bgp_free_msg(msg);
                continue;
            }

            if (atomic_read(&nbr->bgp_state) == BGPS_ESTAB) {
                nbr->msg_stats.upd.rx.cnt++;
                nbr->msg_stats.upd.rx.last_ts = tm;

                /*
                 * Check whether debugging is turned on for inbound updates,
                 * The check here is less strict than is needed to determine
                 * whether output should be generated because it does not test
                 * all of the filter options (for example address family, or
                 * access-list). The check here is used so that the
                 * access-list checks (in bgp4_process_reachables and
                 * bgp4_process_unreachables) are avoided entirely if inbound
                 * updates debugging is turned off.
                 *
                 * Notes:
                 * - The BGP_OPT_NOFILTER option must be used here so
                 *   that any address family or access-list filters are
                 *   ignored.
                 * - The ttylist calculated here is passed to bgp4_rcv_update,
                 *   and is used to display debug messages when errors are
                 *   encountered during processing of the update.
                 */
                bgp_debug_ttys(&debug_update_list, BGP_DEBUG_FLAG_UPD_IN,
                               BGP_AF_NONE, BGP_NBR_TO_VRF_HANDLE(nbr),
                               &nbr->nbrinfo.nbr_addr, B_DIR_IN, NULL, 0,
                               NULL, NULL, BGP_OPT_NOFILTER,
                               BGP_DBG_LEVEL_WARNING);
                debugging_updates = !bgp_debug_list_empty(&debug_update_list);
                if (bgp4_rcv_update(nbr, msg->datagramstart, bytes, msg,
                                    debugging_updates, &debug_update_list)) {
                    if (debugging_updates) {
                        BGP_DEBUG_UPD_IN(BGP_AF_NONE,
                                         BGP_NBR_TO_VRF_HANDLE(nbr),
                                         bgp_nbr_addr(nbr),
                                         B_DIR_IN, NULL, 0, BGP_OPT_DFLT,
                                         BGP_DBG_LEVEL_DETAIL,
                                         "Received UPDATE from %s (length "
                                         "incl. header = %u)",
                                         nbr->neighbor_name, bytes);
                        bgp_dump_msg(BGP_DEBUG_FLAG_UPD_IN,
                                     BGP_NBR_TO_VRF_HANDLE(nbr),
                                     bgp_nbr_addr(nbr), B_DIR_IN,
                                     msg->datagramstart, bytes);
                    }
                }
            } else if (atomic_read(&nbr->bgp_state) != BGPS_CLOSING &&
                       atomic_read(&nbr->bgp_state) != BGPS_CLOSINGSYNC) {
                /*
                 * Neighbor is not established and the neighbor is not
                 * in the closing state. Still we received an update
                 * message which indicates that the neighbor has
                 * a bad FSM implementation. Send notification.
                 */
                BGP_TRACE(BGP_TP_348, "bgp_send_notification", 
                          nbr->neighbor_name, 2, BGP_POSTIT_TYPE_FSM_ERROR, 0);
                bgp_send_notification(nbr, BNOT_FSMERROR, 0, NULL, 0,
                                      NULL, 0, BGP_POSTIT_TYPE_FSM_ERROR);
            }
        }
        
        if (msg != NULL) {
            bgp_free_msg(msg);
        }
    }


    /*
     * Trigger update gen for this neighbor if:
     *     - The delta rt set is non empty AND EoR has been received for 
     *       rt-filter afi, or 60 second timer has expired, OR
     *     - EoR was just received, and hence
     *       we have to force VPN update generation (even though delta
     *       rt set might be empty) 
     * If neither BN_AF2_ENABLE_VPN_UPDATE_GEN nor BN_AF2_TRIGGER_VPN_UPDATE_GEN
     * are set, then the trigger is sent after EoR is received or the 60 
     * second timer expires (at which time BN_AF2_TRIGGER_VPN_UPDATE_GEN will 
     * be set.)
     * Note: We send the trgger even if the vpnvX afis are not out of read-
     *       only mode. thais is because the trigger is used to set the 
     *       BN_AF2_ENABLE_VPN_UPDATE_GEN flag on the rt-filter nbr-af
     */
    if ((bgp_instance_active(&bgp_info)) && 
        (!BGP_NBR_AF_DELETED(nbr_af)) && 
        (((nbr_af->delta_rt_set.size > 0) && 
          ((nbr_af->af2_flags & BN_AF2_ENABLE_VPN_UPDATE_GEN) != 0)) ||
         ((nbr_af->af2_flags & BN_AF2_TRIGGER_VPN_UPDATE_GEN) != 0))) {
        BGP_DEBUG_UPD_IN(BGP_AF_NONE,
                BGP_NBR_TO_VRF_HANDLE(nbr),
                bgp_nbr_addr(nbr),
                B_DIR_IN, NULL, 0, BGP_OPT_DFLT,
                BGP_DBG_LEVEL_DETAIL,
                "Received RT update for neighbor %s. Delta RT set "
                "size %u, Triggering VPN updates",
                nbr->neighbor_name, nbr_af->delta_rt_set.size);
        BGP_TRACE(BGP_TP_756, "Update processed",
                nbr->neighbor_name, nbr_af->delta_rt_set.size);
        BGP_SEND_ASYNC(bgpinfo_update_evm_ctl, BGP_UPD_ASYNC_NBR_RT_UPDATE,
                nbr);
    } else if ((bgp_instance_active(&bgp_info)) && 
               (!BGP_NBR_AF_DELETED(nbr_af)) &&
               ((nbr_af->af2_flags & BN_AF2_ENABLE_VPN_UPDATE_GEN) == 0) &&
               (nbr_af->delta_rt_set.size > initial_delta_rt_set_size)) {
        //Print this message only if new RT updates were received
        BGP_DEBUG_UPD_IN(BGP_AF_NONE,
                BGP_NBR_TO_VRF_HANDLE(nbr),
                bgp_nbr_addr(nbr),
                B_DIR_IN, NULL, 0, BGP_OPT_DFLT,
                BGP_DBG_LEVEL_DETAIL,
                "Received RT update for neighbor %s. Delta RT set size %u. "
                "Suppressing trigger because RT-filter EOR not received",
                nbr->neighbor_name, nbr_af->delta_rt_set.size);
        BGP_TRACE(BGP_TP_776, nbr->neighbor_name);
    }
    
    vrf_ctx = BGP_NBR_TO_VRF(nbr);
    bgp_elapsed_time(&elapsed, &tm);
    bgp_add_time(&bgp_info.perf.allvrfs.upd_in_tm, &elapsed);
    bgp_info.perf.allvrfs.upd_in_msgs += count;
    bgp_add_time(&vrf_ctx->perf.upd_in_tm, &elapsed);
    vrf_ctx->perf.upd_in_msgs += count;
    bgp_add_time(&nbr->perf.upd_in_tm, &elapsed);
    nbr->perf.upd_in_msgs += count;

    return (count);
}

 

/*
 * bgp_router_process_readq
 *
 * Read updates from the neighbor readq.
 */
static void
bgp_router_process_readq (event_context_t *evc,
                          void            *ctx)
{
    bool         read_suspend;     /* True if didn't empty all nbr queues    */
    bool         nbr_read_suspend; /* Whether current nbr queue was emptied  */
    int          msgcount;         /* Total number of messages read          */
    bgp_nbrtype *nbr;              /* Current neighbor                       */
    bgp_nbrtype *next_nbr;         /* Next neighbor to be processed          */
    int          nbr_readmsgs;     /* Number of msgs read from neighbor      */
    bool         first_time;       /* whether first time enter the while loop*/
    int          nbr_readmsgs_per_round;
    bool        *alive;

    /*
     * If BGP gets unconfigured while the router thread is processing a large
     * number of updates, the router thread can get stuck in a busy loop even
     * though the thread has been sent a BGP_ASYNC_DIE signal/alive set to FALSE.  
     *
     * The problem is that the DIE signal gets queued to the router thread/alive 
     * set to FALSE *after* the thread enters the following loops which may take 
     * a long time to complete, so we have to add a check for this alive boolean 
     * inside the loop conditional.
     */
    alive = &bgp_info.thread_info[BGP_ROUTER_THREAD_INDEX].alive;

    /*
     * Reset the boolean so we can be rescheduled
     */
    (void)bgp_boolean_set(bgpinfo_router_rd_bool, FALSE);

    read_suspend = FALSE;
    nbr_read_suspend = FALSE;
    msgcount = 0;
    first_time = TRUE;
    nbr_readmsgs_per_round = 0;

    /*
     * Process messages from the neighbors with non-empty read queues.
     * Processing continues until all messages have been consumed, or
     * more than BGP_UPDRECV_MAX messages have been processed.
     * Messages from neighbors are processed in chunks of BGP_UPDRECV_NBR.
     * The decision of whether to stop or continue processing is only
     * made each time the entire list of pending neighbors has been processed.
     */
    while (bgpinfo_netqueue_list != NULL && msgcount < BGP_UPDRECV_MAX && (*alive)) {
        if (!first_time && nbr_readmsgs_per_round == 0) {
            break;
        }
        first_time = FALSE;
        nbr_readmsgs_per_round = 0;
        nbr = bgpinfo_netqueue_list;
        do {
            /*
             * Note: Neighbors are only removed from bgpinfo_netqueue_list by
             * the router thread, so it is safe to record the next neighbor and
             * know it will still be there at the end of the current iteration
             * (even though bgpinfo_netqueue_mutex is not held).
             */
            next_nbr = nbr->readQ.next_readq_nbr;

            /*
             * No need to read this neighbor's readQ if it is in CLOSING
             * state. Remove the neighbor from the bgpinfo_netqueue_list
             * and move on to the next neighbor.
             */
            if (atomic_read(&nbr->bgp_state) == BGPS_CLOSING) {
                BGP_MUTEX_LOCK(&bgpinfo_netqueue_mutex);

                if (nbr->readQ.prev_readq_ptr != NULL) {
                    *nbr->readQ.prev_readq_ptr = nbr->readQ.next_readq_nbr;
                }
                if (nbr->readQ.next_readq_nbr != NULL) {
                    nbr->readQ.next_readq_nbr->readQ.prev_readq_ptr =
                        nbr->readQ.prev_readq_ptr;
                }
                nbr->readQ.next_readq_nbr = NULL;
                nbr->readQ.prev_readq_ptr = NULL;
                atomic_sub(&bgpinfo_netqueue_nbr_count, 1);
                BGP_MUTEX_UNLOCK(&bgpinfo_netqueue_mutex);

                nbr = next_nbr;
                continue;
            }

            nbr_readmsgs = bgp_docommand(nbr, &nbr_read_suspend,
                                         BGP_UPDRECV_NBR);
            if (nbr_read_suspend) {
                read_suspend = TRUE;
                nbr_read_suspend = FALSE;
            }

            if (nbr_readmsgs != 0) {
                nbr_readmsgs_per_round += nbr_readmsgs;
                msgcount += nbr_readmsgs;
                bgp_nbr_readq_enable(nbr);
            }
            nbr = next_nbr;
        } while (nbr != NULL && (*alive));
    }

 
}


