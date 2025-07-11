void new_setelem(struct nl_sock * socket,char *table_name, char *set_name, void *udata, uint32_t ulen, char *obj_ref, char * input_key, int key_len, char *key_end, int key_end_len, int if_catchall){
    struct nl_msg * msg = nlmsg_alloc();
    struct nlmsghdr *hdr1 = nlmsg_put(
            msg,
            NL_AUTO_PORT, // auto assign current pid
            NL_AUTO_SEQ, // begin wit seq number 0
            NFNL_MSG_BATCH_BEGIN,   // TYPE
            sizeof(struct nfgenmsg),
            NLM_F_REQUEST 
    );

    // struct nfgenmsg * h = static_cast<struct nfgenmsg *>(malloc(sizeof(struct nfgenmsg)));
    struct nfgenmsg * h = (struct nfgenmsg *)(malloc(sizeof(struct nfgenmsg)));

    h->nfgen_family = 2;
    h->version = 0;
    h->res_id = NFNL_SUBSYS_NFTABLES;
    memcpy(nlmsg_data(hdr1), h, sizeof(struct nfgenmsg));

    struct nl_msg * msg2 = nlmsg_alloc();
    struct nlmsghdr *hdr2 = nlmsg_put(
            msg2,
            NL_AUTO_PORT, // auto assign current pid
            NL_AUTO_SEQ, // begin wit seq number 0
            (NFNL_SUBSYS_NFTABLES << 8) | (NFT_MSG_NEWSETELEM),// TYPE
            sizeof(struct nfgenmsg),
            NLM_F_REQUEST|NLM_F_CREATE 
    );

    // struct nfgenmsg * h2 = static_cast<struct nfgenmsg *>(malloc(sizeof(struct nfgenmsg)));
    struct nfgenmsg * h2 = (struct nfgenmsg *)(malloc(sizeof(struct nfgenmsg)));

    h2->nfgen_family = 2;//NFPROTO_IPV4;
    h2->version = 0;
    h2->res_id = NFNL_SUBSYS_NFTABLES;
    memcpy(nlmsg_data(hdr2), h2, sizeof(struct nfgenmsg));
    struct nl_msg * msg3 = nlmsg_alloc();
    struct nlmsghdr *hdr3 = nlmsg_put(
            msg3,
            NL_AUTO_PORT, // auto assign current pid
            NL_AUTO_SEQ, // begin wit seq number 0
            NFNL_MSG_BATCH_END,// TYPE
            sizeof(struct nfgenmsg),
            NLM_F_REQUEST 
    );
    //init msg
    //create test1
    struct nl_msg *elem = nlmsg_alloc();
    struct nl_msg *elem_nest = nlmsg_alloc();
    struct nl_msg *elem_key = nlmsg_alloc();
    struct nl_msg *elem_end = nlmsg_alloc();
    uint64_t key = strtoull(input_key, NULL, 0);
    if(obj_ref)
    	nla_put_string(elem_nest, NFTA_SET_ELEM_OBJREF, obj_ref);
    if(if_catchall){
    	nla_put_u32(elem_nest, NFTA_SET_ELEM_FLAGS, htonl(NFT_SET_ELEM_CATCHALL));
    }
    else{
    	nla_put(elem_key, NFTA_DATA_VALUE, key_len, input_key);
    	if(key_end != NULL){
            nla_put(elem_end, NFTA_DATA_VALUE, key_end_len, key_end);
            nla_put_nested(elem_nest, NFTA_SET_ELEM_KEY_END, elem_end);
    	}
    	nla_put_nested(elem_nest, NFTA_SET_ELEM_KEY, elem_key);
    }
    if(udata != 0){
        nla_put(elem_nest, NFTA_SET_ELEM_USERDATA, ulen, udata);
    }

    nla_put_nested(elem, 1, elem_nest);

    nla_put_string(msg2, NFTA_SET_ELEM_LIST_TABLE, table_name);
    nla_put_string(msg2, NFTA_SET_ELEM_LIST_SET, set_name);
    nla_put_nested(msg2, NFTA_SET_ELEM_LIST_ELEMENTS, elem);
    uint32_t total_size = NLMSG_ALIGN(hdr1->nlmsg_len) + NLMSG_ALIGN(hdr2->nlmsg_len) + NLMSG_ALIGN(hdr3->nlmsg_len);

    // char *buf = static_cast<char *>(malloc(total_size));
    char *buf = (char *)(malloc(total_size));

    memset(buf,0,total_size);
    memcpy(buf,hdr1,NLMSG_ALIGN(hdr1->nlmsg_len));
    memcpy(buf+NLMSG_ALIGN(hdr1->nlmsg_len),hdr2, NLMSG_ALIGN(hdr2->nlmsg_len));
    memcpy(buf+NLMSG_ALIGN(hdr1->nlmsg_len)+NLMSG_ALIGN(hdr2->nlmsg_len),hdr3,NLMSG_ALIGN(hdr3->nlmsg_len));
    int res = nl_sendto(socket, buf, total_size);
    nlmsg_free(msg);
    if (res < 0) {
        fprintf(stderr, "sending message failed\n");
    }
}

void new_setelem_with_expr(struct nl_sock * socket,char *table_name, char *set_name, void *udata, uint32_t ulen, char *obj_ref, char * input_key, int key_len, char *key_end, int key_end_len){
    struct nl_msg * msg = nlmsg_alloc();
    struct nlmsghdr *hdr1 = nlmsg_put(
            msg,
            NL_AUTO_PORT, // auto assign current pid
            NL_AUTO_SEQ, // begin wit seq number 0
            NFNL_MSG_BATCH_BEGIN,   // TYPE
            sizeof(struct nfgenmsg),
            NLM_F_REQUEST 
    );

    // struct nfgenmsg * h = static_cast<struct nfgenmsg *>(malloc(sizeof(struct nfgenmsg)));
    struct nfgenmsg * h = (struct nfgenmsg *)(malloc(sizeof(struct nfgenmsg)));

    h->nfgen_family = 2;
    h->version = 0;
    h->res_id = NFNL_SUBSYS_NFTABLES;
    memcpy(nlmsg_data(hdr1), h, sizeof(struct nfgenmsg));

    struct nl_msg * msg2 = nlmsg_alloc();
    struct nlmsghdr *hdr2 = nlmsg_put(
            msg2,
            NL_AUTO_PORT, // auto assign current pid
            NL_AUTO_SEQ, // begin wit seq number 0
            (NFNL_SUBSYS_NFTABLES << 8) | (NFT_MSG_NEWSETELEM),// TYPE
            sizeof(struct nfgenmsg),
            NLM_F_REQUEST|NLM_F_CREATE 
    );

    // struct nfgenmsg * h2 = static_cast<struct nfgenmsg *>(malloc(sizeof(struct nfgenmsg)));
    struct nfgenmsg * h2 = (struct nfgenmsg *)(malloc(sizeof(struct nfgenmsg)));

    h2->nfgen_family = 2;//NFPROTO_IPV4;
    h2->version = 0;
    h2->res_id = NFNL_SUBSYS_NFTABLES;
    memcpy(nlmsg_data(hdr2), h2, sizeof(struct nfgenmsg));
    struct nl_msg * msg3 = nlmsg_alloc();
    struct nlmsghdr *hdr3 = nlmsg_put(
            msg3,
            NL_AUTO_PORT, // auto assign current pid
            NL_AUTO_SEQ, // begin wit seq number 0
            NFNL_MSG_BATCH_END,// TYPE
            sizeof(struct nfgenmsg),
            NLM_F_REQUEST
    );
    //init msg
    //create test1
    struct nl_msg *elem = nlmsg_alloc();
    struct nl_msg *elem_nest = nlmsg_alloc();
    struct nl_msg *elem_key = nlmsg_alloc();
    struct nl_msg *elem_end = nlmsg_alloc();
    struct nl_msg *elem_expr = nlmsg_alloc();
    struct nl_msg *elem_expr_data = nlmsg_alloc();
    struct nl_msg *elem_expr_data_cmp_data = nlmsg_alloc();
    uint64_t key = strtoull(input_key, NULL, 0);
    nla_put_string(elem_expr, NFTA_EXPR_NAME, "last");
    nla_put_nested(elem_nest, NFTA_SET_ELEM_EXPR, elem_expr);
    nla_put(elem_key, NFTA_DATA_VALUE, key_len, input_key);
    if(key_end != NULL){
            nla_put(elem_end, NFTA_DATA_VALUE, key_end_len, key_end);
            nla_put_nested(elem_nest, NFTA_SET_ELEM_KEY_END, elem_end);
    }
    nla_put_nested(elem_nest, NFTA_SET_ELEM_KEY, elem_key);
    if(obj_ref != NULL)
    	nla_put_string(elem_nest, NFTA_SET_ELEM_OBJREF, obj_ref);
    if(udata != 0){
        nla_put(elem_nest, NFTA_SET_ELEM_USERDATA, ulen, udata);
    }

    nla_put_nested(elem, 1, elem_nest);

    nla_put_string(msg2, NFTA_SET_ELEM_LIST_TABLE, table_name);
    nla_put_string(msg2, NFTA_SET_ELEM_LIST_SET, set_name);
    nla_put_nested(msg2, NFTA_SET_ELEM_LIST_ELEMENTS, elem);
    uint32_t total_size = NLMSG_ALIGN(hdr1->nlmsg_len) + NLMSG_ALIGN(hdr2->nlmsg_len) + NLMSG_ALIGN(hdr3->nlmsg_len);

    // char *buf = static_cast<char *>(malloc(total_size));
    char *buf = (char *)(malloc(total_size));

    memset(buf,0,total_size);
    memcpy(buf,hdr1,NLMSG_ALIGN(hdr1->nlmsg_len));
    memcpy(buf+NLMSG_ALIGN(hdr1->nlmsg_len),hdr2, NLMSG_ALIGN(hdr2->nlmsg_len));
    memcpy(buf+NLMSG_ALIGN(hdr1->nlmsg_len)+NLMSG_ALIGN(hdr2->nlmsg_len),hdr3,NLMSG_ALIGN(hdr3->nlmsg_len));
    int res = nl_sendto(socket, buf, total_size);
    nlmsg_free(msg);
    if (res < 0) {
        fprintf(stderr, "sending message failed\n");
    }
}


void get_setelem(struct nl_sock * socket, char *table_name, char *set_name, char *input_key, int key_len){
    //init msg
    struct nl_msg * msg = nlmsg_alloc();
    nfnlmsg_put(
            msg,
            NL_AUTO_PID, // auto assign current pid
            NL_AUTO_SEQ, // begin wit seq number 0
            NFNL_SUBSYS_NFTABLES,  //SUBSYS
            NFT_MSG_GETSETELEM,   // TYPE
            NLM_F_REQUEST,
            2, //FAMILY
            0           //RES_ID
    );
    //init msg
    struct nl_msg *elem = nlmsg_alloc();
    struct nl_msg *elem_nest = nlmsg_alloc();
    struct nl_msg *elem_key = nlmsg_alloc();

    nla_put(elem_key, NFTA_DATA_VALUE, key_len, input_key);
    nla_put_nested(elem_nest, NFTA_SET_ELEM_KEY, elem_key);
    nla_put_nested(elem, 1, elem_nest);
    nla_put_string(msg, NFTA_SET_ELEM_LIST_TABLE, table_name);
    nla_put_string(msg, NFTA_SET_ELEM_LIST_SET, set_name);
    nla_put_nested(msg, NFTA_SET_ELEM_LIST_ELEMENTS, elem);

    int res = nl_send_auto(socket, msg);
    nlmsg_free(msg);
    if (res < 0) {
        fprintf(stderr, "sending message failed\n");
    }
}

void del_setelem(struct nl_sock * socket, char *table, char *set, char *key, int key_size, char *key_end, int key_end_size){
    struct nl_msg * msg = nlmsg_alloc();
    struct nlmsghdr *hdr1 = nlmsg_put(
            msg,
            NL_AUTO_PORT, // auto assign current pid
            NL_AUTO_SEQ, // begin wit seq number 0
            NFNL_MSG_BATCH_BEGIN,   // TYPE
            sizeof(struct nfgenmsg),
            NLM_F_REQUEST 
    );

    // struct nfgenmsg * h = static_cast<struct nfgenmsg *>(malloc(sizeof(struct nfgenmsg)));
    struct nfgenmsg * h = (struct nfgenmsg *)(malloc(sizeof(struct nfgenmsg)));

    h->nfgen_family = 2;
    h->version = 0;
    h->res_id = NFNL_SUBSYS_NFTABLES;
    memcpy(nlmsg_data(hdr1), h, sizeof(struct nfgenmsg));

    struct nl_msg * msg2 = nlmsg_alloc();
    struct nlmsghdr *hdr2 = nlmsg_put(
            msg2,
            NL_AUTO_PORT, // auto assign current pid
            NL_AUTO_SEQ, // begin wit seq number 0
            (NFNL_SUBSYS_NFTABLES << 8) | (NFT_MSG_DELSETELEM),// TYPE
            sizeof(struct nfgenmsg),
            NLM_F_REQUEST 
    );

    // struct nfgenmsg * h2 = static_cast<struct nfgenmsg *>(malloc(sizeof(struct nfgenmsg)));
    struct nfgenmsg * h2 = (struct nfgenmsg *)(malloc(sizeof(struct nfgenmsg)));

    h2->nfgen_family = 2;//NFPROTO_IPV4;
    h2->version = 0;
    h2->res_id = NFNL_SUBSYS_NFTABLES;
    memcpy(nlmsg_data(hdr2), h2, sizeof(struct nfgenmsg));
    struct nl_msg * msg3 = nlmsg_alloc();
    struct nlmsghdr *hdr3 = nlmsg_put(
            msg3,
            NL_AUTO_PORT, // auto assign current pid
            NL_AUTO_SEQ, // begin wit seq number 0
            NFNL_MSG_BATCH_END,// TYPE
            sizeof(struct nfgenmsg),
            NLM_F_REQUEST
    );
    //init msg
    //create test1
    struct nl_msg *elem = nlmsg_alloc();
    struct nl_msg *elem_nest = nlmsg_alloc();
    struct nl_msg *elem_key = nlmsg_alloc();
    struct nl_msg *elem_key_end = nlmsg_alloc();
    nla_put(elem_key, NFTA_DATA_VALUE, key_size, key);
    nla_put_nested(elem_nest, NFTA_SET_ELEM_KEY, elem_key);
    if(key_end){
    	nla_put(elem_key_end, NFTA_DATA_VALUE, key_end_size, key_end);
    	nla_put_nested(elem_nest, NFTA_SET_ELEM_KEY_END, elem_key_end);
    }
    nla_put_nested(elem, 1, elem_nest);

    nla_put_string(msg2, NFTA_SET_ELEM_LIST_TABLE, table);
    nla_put_string(msg2, NFTA_SET_ELEM_LIST_SET, set);
    nla_put_nested(msg2, NFTA_SET_ELEM_LIST_ELEMENTS, elem);
    uint32_t total_size = NLMSG_ALIGN(hdr1->nlmsg_len) + NLMSG_ALIGN(hdr2->nlmsg_len) + NLMSG_ALIGN(hdr3->nlmsg_len);

    // char *buf = static_cast<char *>(malloc(total_size));
    char *buf = (char *)(malloc(total_size));

    memset(buf,0,total_size);
    memcpy(buf,hdr1,NLMSG_ALIGN(hdr1->nlmsg_len));
    memcpy(buf+NLMSG_ALIGN(hdr1->nlmsg_len), hdr2, NLMSG_ALIGN(hdr2->nlmsg_len));
    memcpy(buf+NLMSG_ALIGN(hdr1->nlmsg_len)+NLMSG_ALIGN(hdr2->nlmsg_len), hdr3, NLMSG_ALIGN(hdr3->nlmsg_len));
    int res = nl_sendto(socket, buf, total_size);
    nlmsg_free(msg);
    if (res < 0) {
        fprintf(stderr, "sending message failed\n");
    } else {
        printf("Delete setelem\n");
    }
}

struct nlmsghdr *new_setelem_msg(char *table_name, char *set_name, void *udata, uint32_t ulen, char *obj_ref, char * input_key, int key_len, char *key_end, int key_end_len){
    struct nl_msg * msg2 = nlmsg_alloc();
    struct nlmsghdr *hdr2 = nlmsg_put(
            msg2,
            NL_AUTO_PORT, // auto assign current pid
            NL_AUTO_SEQ, // begin wit seq number 0
            (NFNL_SUBSYS_NFTABLES << 8) | (NFT_MSG_NEWSETELEM),// TYPE
            sizeof(struct nfgenmsg),
            NLM_F_REQUEST|NLM_F_CREATE
    );

    // struct nfgenmsg * h2 = static_cast<struct nfgenmsg *>(malloc(sizeof(struct nfgenmsg)));
    struct nfgenmsg * h2 = (struct nfgenmsg *)(malloc(sizeof(struct nfgenmsg)));

    h2->nfgen_family = 2;//NFPROTO_IPV4;
    h2->version = 0;
    h2->res_id = NFNL_SUBSYS_NFTABLES;
    memcpy(nlmsg_data(hdr2), h2, sizeof(struct nfgenmsg));
    //init msg
    //create test1
    struct nl_msg *elem = nlmsg_alloc();
    struct nl_msg *elem_nest = nlmsg_alloc();
    struct nl_msg *elem_key = nlmsg_alloc();
    struct nl_msg *elem_end = nlmsg_alloc();
    uint64_t key = strtoull(input_key, NULL, 0);
    nla_put(elem_key, NFTA_DATA_VALUE, key_len, input_key);
    if(key_end != NULL){
            nla_put(elem_end, NFTA_DATA_VALUE, key_end_len, key_end);
            nla_put_nested(elem_nest, NFTA_SET_ELEM_KEY_END, elem_end);
    }
    nla_put_nested(elem_nest, NFTA_SET_ELEM_KEY, elem_key);
    if(obj_ref != NULL)
        nla_put_string(elem_nest, NFTA_SET_ELEM_OBJREF, obj_ref);
    if(udata != 0){
        nla_put(elem_nest, NFTA_SET_ELEM_USERDATA, ulen, udata);
    }

    nla_put_nested(elem, 1, elem_nest);

    nla_put_string(msg2, NFTA_SET_ELEM_LIST_TABLE, table_name);
    nla_put_string(msg2, NFTA_SET_ELEM_LIST_SET, set_name);
    nla_put_nested(msg2, NFTA_SET_ELEM_LIST_ELEMENTS, elem);
    return hdr2;
}
