# Running PLDM Tool with Caliptra MCU Emulator




 Prerequisites
 
Windows 10 version 1903 or higher (with WSL2 enabled)
A WSL2-enabled Linux distro (e.g., Ubuntu)
Virtualization enabled in BIOS

1. Install Docker Desktop
Download from: https://www.docker.com/products/docker-desktop/
Run the installer.
During installation, ensure the option to enable WSL2 integration is selected.


2. Enable WSL Integration in Docker

After installation:
Open Docker Desktop.
Go to Settings → Resources → WSL Integration.
Enable integration for your Linux distro (e.g., Ubuntu).
Apply & Restart Docker.


3. Test Docker in WSL

Open your WSL terminal (e.g., Ubuntu):

```text
docker --version
docker run hello-world
```


4. Create a directory to create a Docker file

```text
mkdir ~/openbmc-pldm-docker
cd ~/openbmc-pldm-docker
cat > Dockerfile << EOF
FROM ubuntu:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    git \
    build-essential \
    cmake \
    ninja-build \
    python3 \
    python3-pip \
    libsystemd-dev \
    pkg-config \
    libgtest-dev \
    libboost-dev \
    libdbus-1-dev \
    && rm -rf /var/lib/apt/lists/*

# Install required Python modules for sdbusplus build
RUN pip3 install --break-system-packages inflection PyYAML mako jsonschema meson

# 🔧 Build sdbusplus
WORKDIR /tmp
RUN git clone https://github.com/openbmc/sdbusplus.git && \
    cd sdbusplus && \
    meson setup build && \
    ninja -C build
EOF
```

5. Build the docker image and name it (e.g. openbmc-pldm). This may take a while

```text
docker build -t openbmc-pldm .
```

6. Create a directory for openbmc pldm repo
``` text
mkdir ~/openbmc
cd ~/openbmc
```

7. Clone openbmc

```text
git clone https://github.com/openbmc/pldm.git
```

8. Checkout the version that was known to be working when this document was created

```text
cd pldm
git checkout 70eca96bebade89aceab0762e3615b816e29fba7
```

9. Apply the patch to bypass MCTP transport and use TCP Socket instead

```text
cat > bypass_mctp.patch << EOF
From 194f40e30b0e826d0dba7a36ce2d58b254344a9e Mon Sep 17 00:00:00 2001
From: Marco Visaya <marcovisaya@microsoft.com>
Date: Wed, 21 May 2025 10:44:10 -0700
Subject: [PATCH] Use TCP as MCTP transport for PLDMTool

---
 common/instance_id.hpp       |  57 ++++------------
 common/transport.cpp         |  89 +++++++++++++++++++++++++
 pldmtool/pldm_cmd_helper.cpp | 122 +++++++++++++++++++++++++++++++++--
 pldmtool/pldm_cmd_helper.hpp |   2 +-
 4 files changed, 220 insertions(+), 50 deletions(-)

diff --git a/common/instance_id.hpp b/common/instance_id.hpp
index 40de1f1..ab31d36 100644
--- a/common/instance_id.hpp
+++ b/common/instance_id.hpp
@@ -17,13 +17,10 @@ namespace pldm
 class InstanceIdDb
 {
   public:
+    uint8_t instanceId = 0; //!< PLDM instance ID
     InstanceIdDb()
     {
-        int rc = pldm_instance_db_init_default(&pldmInstanceIdDb);
-        if (rc)
-        {
-            throw std::system_category().default_error_condition(rc);
-        }
+
     }

     /** @brief Constructor
@@ -32,23 +29,13 @@ class InstanceIdDb
      */
     InstanceIdDb(const std::string& path)
     {
-        int rc = pldm_instance_db_init(&pldmInstanceIdDb, path.c_str());
-        if (rc)
-        {
-            throw std::system_category().default_error_condition(rc);
-        }
+        // avoid warnings
+        (void)path;
     }

     ~InstanceIdDb()
     {
-        /*
-         * Abandon error-reporting. We shouldn't throw an exception from the
-         * destructor, and the class has multiple consumers using incompatible
-         * logging strategies.
-         *
-         * Broadly, it should be possible to use strace to investigate.
-         */
-        pldm_instance_db_destroy(pldmInstanceIdDb);
+
     }

     /** @brief Allocate an instance ID for the given terminus
@@ -58,20 +45,9 @@ class InstanceIdDb
      */
     uint8_t next(uint8_t tid)
     {
-        uint8_t id;
-        int rc = pldm_instance_id_alloc(pldmInstanceIdDb, tid, &id);
-
-        if (rc == -EAGAIN)
-        {
-            throw std::runtime_error("No free instance ids");
-        }
-
-        if (rc)
-        {
-            throw std::system_category().default_error_condition(rc);
-        }
-
-        return id;
+        // avoid warnings
+        (void)tid;
+        return instanceId++;
     }

     /** @brief Mark an instance id as unused
@@ -80,21 +56,12 @@ class InstanceIdDb
      */
     void free(uint8_t tid, uint8_t instanceId)
     {
-        int rc = pldm_instance_id_free(pldmInstanceIdDb, tid, instanceId);
-        if (rc == -EINVAL)
-        {
-            throw std::runtime_error(
-                "Instance ID " + std::to_string(instanceId) + " for TID " +
-                std::to_string(tid) + " was not previously allocated");
-        }
-        if (rc)
-        {
-            throw std::system_category().default_error_condition(rc);
-        }
+        // avoid warnings
+        (void)tid;
+        (void)instanceId;
     }

-  private:
-    pldm_instance_db* pldmInstanceIdDb = nullptr;
+
 };

 } // namespace pldm
diff --git a/common/transport.cpp b/common/transport.cpp
index 5c9678a..3972c63 100644
--- a/common/transport.cpp
+++ b/common/transport.cpp
@@ -7,6 +7,8 @@
 #include <algorithm>
 #include <ranges>
 #include <system_error>
+#include <iostream>
+

 struct pldm_transport* transport_impl_init(TransportImpl& impl, pollfd& pollfd);
 void transport_impl_destroy(TransportImpl& impl);
@@ -31,10 +33,84 @@ static constexpr uint8_t MCTP_EID_VALID_MAX = 255;
  * prevent the failure of pldm_transport_mctp_demux_recv().
  */

+
+
+
+static pldm_requester_rc_t mock_recv(struct pldm_transport *transport,
+                                     pldm_tid_t *tid, void **pldm_resp_msg,
+                                     size_t *msg_len) {
+
+    // avoid unused variable warning
+    (void)transport;
+    (void)tid;
+    (void)pldm_resp_msg;
+    (void)msg_len;
+
+    return PLDM_REQUESTER_SUCCESS;
+}
+
+static pldm_requester_rc_t mock_send(struct pldm_transport *transport,
+                                     pldm_tid_t tid, const void *pldm_msg,
+                                     size_t msg_len) {
+
+// avoid unused variable warning
+    (void)transport;
+    (void)tid;
+    (void)pldm_msg;
+    (void)msg_len;
+
+    return PLDM_REQUESTER_SUCCESS;
+}
+
+static int mock_init_pollfd(struct pldm_transport *transport,
+                            struct pollfd *pollfd) {
+    // avoid unused variable warning
+    (void)transport;
+    pollfd->fd = -1;          // No real fd
+    pollfd->events = POLLIN;  // Simulate input
+    return 0;
+}
+
+
+struct pldm_transport_mock {
+       const char *name;
+       uint8_t version;
+       pldm_requester_rc_t (*recv)(struct pldm_transport *transport,
+                                   pldm_tid_t *tid, void **pldm_resp_msg,
+                                   size_t *msg_len);
+       pldm_requester_rc_t (*send)(struct pldm_transport *transport,
+                                   pldm_tid_t tid, const void *pldm_msg,
+                                   size_t msg_len);
+       int (*init_pollfd)(struct pldm_transport *transport,
+                          struct pollfd *pollfd);
+};
+
+
+struct pldm_transport *create_mock_transport(TransportImpl& impl, pollfd& pollfd) {
+    static struct pldm_transport_mock t;
+    t.name = "mock_transport";
+    t.version = 1;
+    t.recv = mock_recv;
+    t.send = mock_send;
+    t.init_pollfd = mock_init_pollfd;
+
+    impl.mctp_demux = (struct pldm_transport_mctp_demux*)&t;
+
+    (void)pollfd;
+    return (struct pldm_transport *)&t;
+}
+
+
 [[maybe_unused]] static struct pldm_transport*
     pldm_transport_impl_mctp_demux_init(TransportImpl& impl, pollfd& pollfd)
 {
+
+    // avoid unused variable warning
+    (void)pollfd;
+    // print debug message
+    std::cerr << "marco: PLDM transport using MCTP demux" << std::endl;
     impl.mctp_demux = nullptr;
+    /*
     pldm_transport_mctp_demux_init(&impl.mctp_demux);
     if (!impl.mctp_demux)
     {
@@ -60,12 +136,18 @@ static constexpr uint8_t MCTP_EID_VALID_MAX = 255;
         pldm_transport_mctp_demux_init_pollfd(pldmTransport, &pollfd);
     }

+    // print pldmTransport
+    std::cerr << "marco: pldmTransport: " << pldmTransport << std::endl;
     return pldmTransport;
+    */
+   std::cerr << "marco: return Null: " << std::endl;
+   return nullptr;
 }

 [[maybe_unused]] static struct pldm_transport* pldm_transport_impl_af_mctp_init(
     TransportImpl& impl, pollfd& pollfd)
 {
+    std::cerr << "marco: pldm_transport_impl_af_mctp_init" << std::endl;
     impl.af_mctp = nullptr;
     pldm_transport_af_mctp_init(&impl.af_mctp);
     if (!impl.af_mctp)
@@ -102,6 +184,8 @@ static constexpr uint8_t MCTP_EID_VALID_MAX = 255;

 struct pldm_transport* transport_impl_init(TransportImpl& impl, pollfd& pollfd)
 {
+    std::cerr << "marco: transport_impl_init" << std::endl;
+#if 0
 #if defined(PLDM_TRANSPORT_WITH_MCTP_DEMUX)
     return pldm_transport_impl_mctp_demux_init(impl, pollfd);
 #elif defined(PLDM_TRANSPORT_WITH_AF_MCTP)
@@ -109,6 +193,11 @@ struct pldm_transport* transport_impl_init(TransportImpl& impl, pollfd& pollfd)
 #else
     return nullptr;
 #endif
+#else
+
+    return create_mock_transport(impl, pollfd);
+#endif
+std::cerr << "marco: transport_impl_init done" << std::endl;
 }

 void transport_impl_destroy(TransportImpl& impl)
diff --git a/pldmtool/pldm_cmd_helper.cpp b/pldmtool/pldm_cmd_helper.cpp
index cbcf827..f07a7d4 100644
--- a/pldmtool/pldm_cmd_helper.cpp
+++ b/pldmtool/pldm_cmd_helper.cpp
@@ -17,11 +17,110 @@

 using namespace pldm::utils;

+#include <string>
+#include <netinet/in.h>
+#include <unistd.h>
+#include <arpa/inet.h>
+#include <iostream>
+using namespace std;
+
+class CaliptraEmulatorClient {
+public:
+    CaliptraEmulatorClient(const std::string& server_ip, uint16_t server_port);
+    ~CaliptraEmulatorClient();
+
+    bool connect_to_server();
+    bool send_message(const std::vector<uint8_t>& data);
+    bool receive_data(std::vector<uint8_t>& buffer);
+    void close();
+
+private:
+    std::string server_ip_;
+    uint16_t server_port_;
+    int sock_fd_;
+    bool connected_;
+};
+
+#include <cstring>
+#include <sys/socket.h>
+
+CaliptraEmulatorClient::CaliptraEmulatorClient(const std::string& server_ip, uint16_t server_port)
+    : server_ip_(server_ip), server_port_(server_port), sock_fd_(-1), connected_(false) {}
+
+CaliptraEmulatorClient::~CaliptraEmulatorClient() {
+    close();
+}
+
+bool CaliptraEmulatorClient::connect_to_server() {
+    sock_fd_ = socket(AF_INET, SOCK_STREAM, 0);
+    std::cerr << "Marco connect_to_server() " << std::endl;
+    if (sock_fd_ < 0) {
+        perror("Socket creation failed");
+        return false;
+    }
+
+    sockaddr_in server_addr{};
+    server_addr.sin_family = AF_INET;
+    server_addr.sin_port = htons(server_port_);
+
+    if (inet_pton(AF_INET, server_ip_.c_str(), &server_addr.sin_addr) <= 0) {
+        perror("Invalid address");
+        return false;
+    }
+
+    if (connect(sock_fd_, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
+        perror("Connection failed");
+        return false;
+    }
+
+    connected_ = true;
+    std::cout << "Connected to server " << server_ip_ << ":" << server_port_ << std::endl;
+    return true;
+}
+
+bool CaliptraEmulatorClient::send_message(const std::vector<uint8_t>& data) {
+    if (!connected_)  {
+        connect_to_server();
+        if (!connected_) {
+            std::cerr << "Failed to connect to server." << std::endl;
+            return false;
+        }
+    }
+    ssize_t sent = write(sock_fd_, data.data(), data.size());
+    return sent == static_cast<ssize_t>(data.size());
+}
+
+bool CaliptraEmulatorClient::receive_data(std::vector<uint8_t>& buffer) {
+
+    if (!connected_)  {
+        connect_to_server();
+        if (!connected_) {
+            std::cerr << "Failed to connect to server." << std::endl;
+            return {};
+        }
+    }
+
+    uint8_t temp[512];
+    ssize_t len = read(sock_fd_, temp, sizeof(temp));
+    if (len <= 0) return false;
+
+    buffer.assign(temp, temp + len);
+    return true;
+}
+
+void CaliptraEmulatorClient::close() {
+    if (connected_) {
+        ::close(sock_fd_);
+        connected_ = false;
+    }
+}
+
 namespace pldmtool
 {
 namespace helper
 {

+
 static const std::map<uint8_t, std::string> genericCompletionCodes{
     {PLDM_SUCCESS, "SUCCESS"},
     {PLDM_ERROR, "ERROR"},
@@ -85,32 +184,42 @@ void fillCompletionCode(uint8_t completionCode, ordered_json& data,

     data["CompletionCode"] = "UNKNOWN_COMPLETION_CODE";
 }
-
+static CaliptraEmulatorClient client("172.27.179.241", 7878);
+static u_int32_t instance_id = 1;
 void CommandInterface::exec()
 {
+    std::cerr <<" Marco : commandInterface::exec() "<< std::endl;
+    /*
     instanceId = instanceIdDb.next(mctp_eid);
+    */
+    instanceId = instance_id++;
     auto [rc, requestMsg] = createRequestMsg();
     if (rc != PLDM_SUCCESS)
     {
-        instanceIdDb.free(mctp_eid, instanceId);
+    //    instanceIdDb.free(mctp_eid, instanceId);
         std::cerr << "Failed to encode request message for " << pldmType << ":"
                   << commandName << " rc = " << rc << "\n";
         return;
     }

     std::vector<uint8_t> responseMsg;
+    client.send_message(requestMsg);
+    client.receive_data(responseMsg);
+    /*
     rc = pldmSendRecv(requestMsg, responseMsg);

     if (rc != PLDM_SUCCESS)
     {
-        instanceIdDb.free(mctp_eid, instanceId);
+        // instanceIdDb.free(mctp_eid, instanceId);
         std::cerr << "pldmSendRecv: Failed to receive RC = " << rc << "\n";
         return;
     }
+        */

     auto responsePtr = reinterpret_cast<struct pldm_msg*>(responseMsg.data());
     parseResponseMsg(responsePtr, responseMsg.size() - sizeof(pldm_msg_hdr));
-    instanceIdDb.free(mctp_eid, instanceId);
+    // instanceIdDb.free(mctp_eid, instanceId);
+
 }

 int CommandInterface::pldmSendRecv(std::vector<uint8_t>& requestMsg,
@@ -128,6 +237,11 @@ int CommandInterface::pldmSendRecv(std::vector<uint8_t>& requestMsg,
         printBuffer(Tx, requestMsg);
     }

+        // dump the request message
+        std::cout << "pldmtool: ";
+        printBuffer(Tx, requestMsg);
+
+
     auto tid = mctp_eid;
     PldmTransport pldmTransport{};
     uint8_t retry = 0;
diff --git a/pldmtool/pldm_cmd_helper.hpp b/pldmtool/pldm_cmd_helper.hpp
index de33d53..5d41156 100644
--- a/pldmtool/pldm_cmd_helper.hpp
+++ b/pldmtool/pldm_cmd_helper.hpp
@@ -148,7 +148,7 @@ class CommandInterface

   protected:
     uint8_t instanceId;
-    pldm::InstanceIdDb instanceIdDb;
+//    pldm::InstanceIdDb instanceIdDb;
     uint8_t numRetries = 0;
 };

--
2.34.1
EOF

```

```text
git apply bypass_mctp.patch
```

Note: please change the IP address in pldm_cmd_helper.cpp to the IP address of your WSL
Find this code:
```text
static CaliptraEmulatorClient client("172.27.179.241", 7878);
```

and replace 172.27.179.241 with your WSL's IP address

10. Create a Docker container "openbmc-dev" from the Docker image "openbmc-pldm"

This will create a mount the current directory (i.e. "~/openbmc/pldm") to Docker's directory "/workspace".
It will also automatically take you to the Ubuntu Docker console

```text
docker run -it --name openbmc-dev  --network host  -v "$PWD:/workspace"   openbmc-pldm
```

11. In the Docker console, install other necessary dependencies

```
apt update
apt install dbus
apt-get install libjson-c-dev
```

12. Build openbmc-pldm repo

```
cd /workspace
meson setup build
ninja -C build
```

13. This should compile the pldmtool executable in build/pldmtool/pldmtool

14. Open another WSL bash and update the caliptra-mcu-sw so that PLDMtool can connect to it.


```
cd caliptra-mcu-sw

# this was the version when this document was created
git checkout 21c8aba9890dba2b907524cca0a1f8054ecd9b0a

cat >> 1.patch <<EOF
From bf9c8145c14afe4eaa74ef6e96f6e81275b009a8 Mon Sep 17 00:00:00 2001
From: Marco Visaya <marcovisaya@microsoft.com>
Date: Wed, 21 May 2025 11:08:47 -0700
Subject: [PATCH] patch

---
 Cargo.lock                                  |  6 ++
 Cargo.toml                                  |  2 +
 emulator/app/Cargo.toml                     |  1 +
 emulator/app/src/main.rs                    | 32 +++++++--
 emulator/bmc/pldm-ua-external/Cargo.toml    |  6 ++
 emulator/bmc/pldm-ua-external/src/lib.rs    |  1 +
 emulator/bmc/pldm-ua-external/src/main.rs   | 11 +++
 emulator/bmc/pldm-ua-external/src/server.rs | 77 +++++++++++++++++++++
 8 files changed, 129 insertions(+), 7 deletions(-)
 create mode 100644 emulator/bmc/pldm-ua-external/Cargo.toml
 create mode 100644 emulator/bmc/pldm-ua-external/src/lib.rs
 create mode 100644 emulator/bmc/pldm-ua-external/src/main.rs
 create mode 100644 emulator/bmc/pldm-ua-external/src/server.rs

diff --git a/Cargo.lock b/Cargo.lock
index 2c973694..40b1e368 100644
--- a/Cargo.lock
+++ b/Cargo.lock
@@ -1375,6 +1375,7 @@ dependencies = [
  "pldm-common",
  "pldm-fw-pkg",
  "pldm-ua",
+ "pldm-ua-external",
  "rand",
  "sec1",
  "sha2",
@@ -2516,6 +2517,7 @@ dependencies = [
  "embedded-alloc",
  "libsyscall-caliptra",
  "libtock_alarm",
+ "libtock_console",
  "libtock_platform",
  "libtock_runtime",
  "libtock_unittest",
@@ -2536,6 +2538,10 @@ dependencies = [
  "uuid",
 ]

+[[package]]
+name = "pldm-ua-external"
+version = "0.1.0"
+
 [[package]]
 name = "polyval"
 version = "0.6.2"
diff --git a/Cargo.toml b/Cargo.toml
index ed88324b..c68c53d2 100644
--- a/Cargo.toml
+++ b/Cargo.toml
@@ -7,6 +7,7 @@ members = [
     "emulator/app",
     "emulator/bmc/pldm-ua",
     "emulator/bmc/pldm-fw-pkg",
+    "emulator/bmc/pldm-ua-external",
     "emulator/bus",
     "emulator/caliptra",
     "emulator/compliance-test",
@@ -140,6 +141,7 @@ mcu-rom-common = { path = "rom" }
 pldm-common = { path = "common/pldm"}
 pldm-fw-pkg = { path = "emulator/bmc/pldm-fw-pkg" }
 pldm-ua = { path = "emulator/bmc/pldm-ua"}
+pldm-ua-external = { path = "emulator/bmc/pldm-ua-external"}


 registers-generated = { path = "registers/generated-firmware" }
diff --git a/emulator/app/Cargo.toml b/emulator/app/Cargo.toml
index a05d3d30..9a7a516f 100644
--- a/emulator/app/Cargo.toml
+++ b/emulator/app/Cargo.toml
@@ -38,6 +38,7 @@ p384.workspace = true
 pldm-common.workspace = true
 pldm-fw-pkg.workspace = true
 pldm-ua.workspace = true
+pldm-ua-external.workspace = true
 rand.workspace = true
 sec1.workspace = true
 sha2.workspace = true
diff --git a/emulator/app/src/main.rs b/emulator/app/src/main.rs
index 463c0684..a4dfbf73 100644
--- a/emulator/app/src/main.rs
+++ b/emulator/app/src/main.rs
@@ -40,7 +40,7 @@ use gdb::gdb_target::GdbTarget;
 use mctp_transport::MctpTransport;
 use pldm_fw_pkg::FirmwareManifest;
 use pldm_ua::daemon::PldmDaemon;
-use pldm_ua::transport::{EndpointId, PldmTransport};
+use pldm_ua::transport::{EndpointId, PldmSocket, PldmTransport};
 use std::cell::RefCell;
 use std::fs::File;
 use std::io;
@@ -52,6 +52,7 @@ use std::sync::atomic::AtomicBool;
 use std::sync::{Arc, Mutex};
 use tests::mctp_util::base_protocol::LOCAL_TEST_ENDPOINT_EID;
 use tests::pldm_request_response_test::PldmRequestResponseTest;
+use pldm_ua_external;

 #[derive(Parser)]
 #[command(version, about, long_about = None, name = "Caliptra MCU Emulator")]
@@ -516,12 +517,28 @@ fn run(cli: Emulator, capture_uart_output: bool) -> io::Result<Vec<u8>> {

     if cfg!(feature = "test-pldm-fw-update-e2e") {
         i3c_controller.start();
-        let pldm_transport =
-            MctpTransport::new(cli.i3c_port.unwrap(), i3c.get_dynamic_address().unwrap());
-        let pldm_socket = pldm_transport
-            .create_socket(EndpointId(8), EndpointId(0))
-            .unwrap();
-        tests::pldm_fw_update_test::PldmFwUpdateTest::run(pldm_socket, running.clone());
+        use std::sync::Arc;
+
+        std::thread::spawn(move || {
+            let pldm_transport = MctpTransport::new(cli.i3c_port.unwrap(), i3c_dynamic_address);
+            let pldm_socket = Arc::new(
+                pldm_transport
+                    .create_socket(EndpointId(LOCAL_TEST_ENDPOINT_EID), EndpointId(1))
+                    .unwrap(),
+            );
+            pldm_ua_external::server::start("172.27.179.241:7878", {
+                let pldm_socket = Arc::clone(&pldm_socket);
+                move |data: &[u8]| -> Vec<u8> {
+                    println!("Callback triggered with {} bytes", data.len());
+
+                    pldm_socket.send(data).unwrap();
+                    let res = pldm_socket.receive(None).unwrap();
+                    res.payload.data[..res.payload.len].to_vec()
+
+                }
+            }).unwrap();
+            println!("Server died");
+        });
     }

     let create_flash_controller =
@@ -740,6 +757,7 @@ fn run(cli: Emulator, capture_uart_output: bool) -> io::Result<Vec<u8>> {
         };
     }

+
     // Check if Optional GDB Port is passed
     match cli.gdb_port {
         Some(port) => {
diff --git a/emulator/bmc/pldm-ua-external/Cargo.toml b/emulator/bmc/pldm-ua-external/Cargo.toml
new file mode 100644
index 00000000..4a22733a
--- /dev/null
+++ b/emulator/bmc/pldm-ua-external/Cargo.toml
@@ -0,0 +1,6 @@
+[package]
+name = "pldm-ua-external"
+version = "0.1.0"
+edition = "2021"
+
+[dependencies]
diff --git a/emulator/bmc/pldm-ua-external/src/lib.rs b/emulator/bmc/pldm-ua-external/src/lib.rs
new file mode 100644
index 00000000..bfe15ae4
--- /dev/null
+++ b/emulator/bmc/pldm-ua-external/src/lib.rs
@@ -0,0 +1 @@
+pub mod server;
\ No newline at end of file
diff --git a/emulator/bmc/pldm-ua-external/src/main.rs b/emulator/bmc/pldm-ua-external/src/main.rs
new file mode 100644
index 00000000..339c80d4
--- /dev/null
+++ b/emulator/bmc/pldm-ua-external/src/main.rs
@@ -0,0 +1,11 @@
+mod server;
+
+
+fn main() -> std::io::Result<()> {
+    server::start("172.27.179.241:7878", |data: &[u8]| -> Vec<u8> {
+        println!("Callback triggered with {} bytes", data.len());
+
+        // Example: echo back uppercase version of each byte (dummy transformation)
+        data.iter().map(|b| b.to_ascii_uppercase()).collect()
+    })
+}
diff --git a/emulator/bmc/pldm-ua-external/src/server.rs b/emulator/bmc/pldm-ua-external/src/server.rs
new file mode 100644
index 00000000..ded8f767
--- /dev/null
+++ b/emulator/bmc/pldm-ua-external/src/server.rs
@@ -0,0 +1,77 @@
+use std::io::{Read, Write};
+use std::net::{TcpListener, TcpStream};
+use std::thread;
+use std::time::Duration;
+
+/// `callback` takes received data as `&[u8]` and returns a response as `Vec<u8>`
+pub fn start<F>(address: &str, callback: F) -> std::io::Result<()>
+where
+    F: Fn(&[u8]) -> Vec<u8> + Send + Sync + 'static,
+{
+    let listener = TcpListener::bind(address)?;
+    let callback = std::sync::Arc::new(callback);
+    println!("Server listening on {}", address);
+
+    for stream in listener.incoming() {
+        match stream {
+            Ok(stream) => {
+                let cb = callback.clone();
+                thread::spawn(move || handle_client(stream, cb));
+            }
+            Err(e) => eprintln!("Connection failed: {}", e),
+        }
+    }
+
+    Ok(())
+}
+
+fn handle_client<F>(mut stream: TcpStream, callback: std::sync::Arc<F>)
+where
+    F: Fn(&[u8]) -> Vec<u8> + Send + Sync + 'static,
+{
+    let peer_addr = stream.peer_addr().unwrap_or_else(|_| "<unknown>".parse().unwrap());
+    println!("New connection from {}", peer_addr);
+
+    let mut buffer = [0u8; 512];
+
+    loop {
+        match stream.read(&mut buffer) {
+            Ok(0) => {
+                println!("Connection from {} closed", peer_addr);
+                break;
+            }
+            Ok(n) => {
+                let data = &buffer[..n];
+
+                // Call the user-supplied callback with the received data
+                let response = callback(data);
+
+                // Print the input
+                let hex_input = data.iter()
+                    .map(|b| format!("0x{:02X}", b))
+                    .collect::<Vec<_>>()
+                    .join(", ");
+                println!("Received from PLDMTool {}: [{}]", peer_addr, hex_input);
+
+                // Print response
+                let hex_response = response.iter()
+                    .map(|b| format!("0x{:02X}", b))
+                    .collect::<Vec<_>>()
+                    .join(", ");
+                println!("Sending to PLDMTool {}: [{}]", peer_addr, hex_response);
+
+                // Send the response back to the client
+                if let Err(e) = stream.write_all(&response) {
+                    eprintln!("Failed to send response to {}: {}", peer_addr, e);
+                    break;
+                }
+            }
+            Err(e) => {
+                eprintln!("Error reading from {}: {}", peer_addr, e);
+                break;
+            }
+        }
+
+        thread::sleep(Duration::from_millis(100));
+    }
+}
--
2.34.1

EOF
```

```
git apply 1.patch
```

Change the IP address in emulator's main.rs from "172.27.179.241" to the IP address of your WSL.

15. Build and run the pldm-fw-update-e2e integration test

```text
cargo test --package tests-integration --lib -- test::test_pldm_fw_update_e2e
```

16. In the Docker console, execute a PLDM command
```text
./build/pldmtool/pldmtool fw_update RequestUpdate --max_transfer_size 128 --num_comps 1 --max_transfer_reqs 1 --package_data_length 1024 --comp_img_ver_str_type "ASCII" --comp_img_ver_str_len 10 --comp_img_set_ver_str "1234567890"

```


