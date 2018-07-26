MSG_TYPES = { 1: "HELLO",
              2: "DBDESC",
              3: "LSREQ",
              4: "LSUPD",
              5: "LSACK",
            }

LSAV3_TYPES = { 8193: "ROUTER",             # links between routers in the area, 0X2001
              8194: "NETWORK",            # links between "networks" in the area, 0X2002
              8195: "INTER AREA PREFIX",
              8196: "INTER AREA ROUTER",
              16389: "EXTERNAL AS",   #0X4005

              8198: "GROUP MEMBER", #0X2006
              8199: "NSSA",
              8: "LINK LSA", #0X0008
              8201: "INTRA AREA PREFIX", #0X2009
              }
