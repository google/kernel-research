void new_set_pipapo(struct nl_sock * socket, char *table_name, char *set_name, int key_len, uint32_t obj_type){
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
            (NFNL_SUBSYS_NFTABLES << 8) | (NFT_MSG_NEWSET),// TYPE
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
    struct nl_msg *data = nlmsg_alloc();
    struct nl_msg *data_nest = nlmsg_alloc();
    struct nl_msg *data_nest_nest = nlmsg_alloc();
    //init IPSET_ATTR_DATA

    int i=0;

    nla_put_u32(data_nest_nest, NFTA_SET_FIELD_LEN, htonl(0x10));
    for(i=0;i<4;i++){
        nla_put_nested(data_nest, NFTA_LIST_ELEM, data_nest_nest);
    }

    nla_put_nested(data, NFTA_SET_DESC_CONCAT, data_nest);
    //create test1
    nla_put_string(msg2, NFTA_SET_TABLE, table_name);
    nla_put_string(msg2, NFTA_SET_NAME, set_name);
    nla_put_u32(msg2, NFTA_SET_ID, 0x10);
    nla_put_nested(msg2, NFTA_SET_DESC, data);
    nla_put_u32(msg2, NFTA_SET_KEY_LEN, htonl(key_len));
    nla_put_u32(msg2, NFTA_SET_FLAGS, htonl(NFT_SET_INTERVAL|NFT_SET_OBJECT|NFT_SET_CONCAT));
    nla_put_u32(msg2, NFTA_SET_OBJ_TYPE, htonl(obj_type));
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

void new_set_bitmap(struct nl_sock * socket, char *table_name, char *set_name){
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
            (NFNL_SUBSYS_NFTABLES << 8) | (NFT_MSG_NEWSET),// TYPE
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
    nla_put_string(msg2, NFTA_SET_TABLE, table_name);
    nla_put_string(msg2, NFTA_SET_NAME, set_name);
    nla_put_u32(msg2, NFTA_SET_KEY_LEN, htonl(2));
    nla_put_u32(msg2, NFTA_SET_ID, 0x10);
    uint32_t total_size = NLMSG_ALIGN(hdr1->nlmsg_len) + NLMSG_ALIGN(hdr2->nlmsg_len) + NLMSG_ALIGN(hdr3->nlmsg_len);
    char *buf = static_cast<char *>(malloc(total_size));
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

struct nlmsghdr *del_set_msg(char *table_name, char *set_name){
    struct nl_msg * msg2 = nlmsg_alloc();
    struct nlmsghdr *hdr2 = nlmsg_put(
            msg2,
            NL_AUTO_PORT, // auto assign current pid
            NL_AUTO_SEQ, // begin wit seq number 0
            (NFNL_SUBSYS_NFTABLES << 8) | (NFT_MSG_DELSET),// TYPE
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
    nla_put_string(msg2, NFTA_SET_TABLE, table_name);
    nla_put_string(msg2, NFTA_SET_NAME, set_name);
    return hdr2;
}
