# Overview

This is an example from this [blog post](blog.sachasmart.com/docker-lambda/), which shows how to run AWS Lambda functions locally using Docker.

### Difference between original runtime and custom runtime

```diff
--- bootstrap.py	2024-04-29 13:13:32.000000000 -0400
+++ originals/bootstrap.og.py	2024-04-29 13:09:48.000000000 -0400
@@ -11,7 +11,6 @@
 import traceback
 import warnings

-import rapid_client
 from lambda_runtime_client import LambdaRuntimeClient
 from lambda_runtime_exception import FaultException
 from lambda_runtime_log_utils import (
@@ -55,7 +54,6 @@
             if pathname is not None:
                 pathname = [pathname]
             file_handle, pathname, desc = imp.find_module(segment, pathname)
-
         if file_handle is None:
             module_type = desc[2]
             if module_type == imp.C_BUILTIN:
@@ -592,50 +590,48 @@
     sys.stdout = Unbuffered(sys.stdout)
     sys.stderr = Unbuffered(sys.stderr)

-    log_sink = create_log_sink()
-    lambda_runtime_api_addr = os.environ["AWS_LAMBDA_RUNTIME_API"]
-    lambda_runtime_client = LambdaRuntimeClient(lambda_runtime_api_addr)
-    try:
-        _setup_logging(_AWS_LAMBDA_LOG_FORMAT, _AWS_LAMBDA_LOG_LEVEL, log_sink)
-
-        global _GLOBAL_AWS_REQUEST_ID
-
-        set_default_sys_path()
-        add_default_site_directories()
-        set_default_pythonpath()
-
-    except Exception:
-        error_result = build_fault_result(sys.exc_info(), None)
-
-        log_error(error_result, log_sink)
-        lambda_runtime_client.post_init_error(to_json(error_result))
-
-        sys.exit(1)
-
-    while True:
-        handler = os.environ["_HANDLER"]
-        request_handler = _get_handler(handler)
-
-        event_request = lambda_runtime_client.wait_next_invocation()
-
-        _GLOBAL_AWS_REQUEST_ID = event_request.invoke_id
-
-        update_xray_env_variable(event_request.x_amzn_trace_id)
-
-        handle_event_request(
-            lambda_runtime_client,
-            request_handler,
-            event_request.invoke_id,
-            event_request.event_body,
-            event_request.content_type,
-            event_request.client_context,
-            event_request.cognito_identity,
-            event_request.invoked_function_arn,
-            event_request.deadline_time_in_ms,
-            log_sink,
-        )
-
-        rapid_client.next()
+    with create_log_sink() as log_sink:
+        lambda_runtime_api_addr = os.environ["AWS_LAMBDA_RUNTIME_API"]
+        lambda_runtime_client = LambdaRuntimeClient(lambda_runtime_api_addr)
+
+        try:
+            _setup_logging(_AWS_LAMBDA_LOG_FORMAT, _AWS_LAMBDA_LOG_LEVEL, log_sink)
+
+            global _GLOBAL_AWS_REQUEST_ID
+
+            set_default_sys_path()
+            add_default_site_directories()
+            set_default_pythonpath()
+
+            handler = os.environ["_HANDLER"]
+            request_handler = _get_handler(handler)
+        except Exception:
+            error_result = build_fault_result(sys.exc_info(), None)
+
+            log_error(error_result, log_sink)
+            lambda_runtime_client.post_init_error(to_json(error_result))
+
+            sys.exit(1)
+
+        while True:
+            event_request = lambda_runtime_client.wait_next_invocation()
+
+            _GLOBAL_AWS_REQUEST_ID = event_request.invoke_id
+
+            update_xray_env_variable(event_request.x_amzn_trace_id)
+
+            handle_event_request(
+                lambda_runtime_client,
+                request_handler,
+                event_request.invoke_id,
+                event_request.event_body,
+                event_request.content_type,
+                event_request.client_context,
+                event_request.cognito_identity,
+                event_request.invoked_function_arn,
+                event_request.deadline_time_in_ms,
+                log_sink,
+            )


 if __name__ == "__main__":
```
