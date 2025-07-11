void new_table(struct nl_sock * socket, char *name){
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

    h->nfgen_family = 2;//NFPROTO_IPV4;
    h->version = 0;
    h->res_id = NFNL_SUBSYS_NFTABLES;
    memcpy(nlmsg_data(hdr1), h, sizeof(struct nfgenmsg));

    struct nl_msg * msg2 = nlmsg_alloc();
    struct nlmsghdr *hdr2 = nlmsg_put(
            msg2,
            NL_AUTO_PORT, // auto assign current pid
            NL_AUTO_SEQ, // begin wit seq number 0
            (NFNL_SUBSYS_NFTABLES << 8) | (NFT_MSG_NEWTABLE),// TYPE
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
    nla_put_string(msg2, NFTA_TABLE_NAME, name);
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

void get_table(struct nl_sock * socket, char *name){
    //init msg
    struct nl_msg * msg = nlmsg_alloc();
    nfnlmsg_put(
            msg,
            NL_AUTO_PID, // auto assign current pid
            NL_AUTO_SEQ, // begin wit seq number 0
            NFNL_SUBSYS_NFTABLES,  //SUBSYS
            NFT_MSG_GETTABLE,   // TYPE
            NLM_F_REQUEST,
            2, //FAMILY
            0           //RES_ID
    );
    //init msg
    nla_put_string(msg, NFTA_TABLE_NAME, name);

    int res = nl_send_auto(socket, msg);
    nlmsg_free(msg);
    if (res < 0) {
        fprintf(stderr, "sending message failed\n");
    }
}

void new_table_with_udata(struct nl_sock * socket, char *name,char *udata, int len){
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

    h->nfgen_family = 2;//NFPROTO_IPV4;
    h->version = 0;
    h->res_id = NFNL_SUBSYS_NFTABLES;
    memcpy(nlmsg_data(hdr1), h, sizeof(struct nfgenmsg));

    struct nl_msg * msg2 = nlmsg_alloc();
    struct nlmsghdr *hdr2 = nlmsg_put(
            msg2,
            NL_AUTO_PORT, // auto assign current pid
            NL_AUTO_SEQ, // begin wit seq number 0
            (NFNL_SUBSYS_NFTABLES << 8) | (NFT_MSG_NEWTABLE),// TYPE
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
    nla_put_string(msg2, NFTA_TABLE_NAME, name);
    nla_put(msg2,NFTA_TABLE_USERDATA,len,udata);
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

void del_table(struct nl_sock * socket, char *table_name){

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
            (NFNL_SUBSYS_NFTABLES << 8) | (NFT_MSG_DELTABLE),// TYPE
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

    nla_put_string(msg2, NFTA_TABLE_NAME, table_name);

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
