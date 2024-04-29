"""
Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
"""

import json
import logging
import os
import site
import sys
import time
import traceback
import warnings

from lambda_runtime_client import LambdaRuntimeClient
from lambda_runtime_exception import FaultException
from lambda_runtime_log_utils import (
    _DATETIME_FORMAT,
    _DEFAULT_FRAME_TYPE,
    _JSON_FRAME_TYPES,
    _TEXT_FRAME_TYPES,
    JsonFormatter,
    LogFormat,
    _format_log_level,
    _get_log_level_from_env_var,
)
from lambda_runtime_marshaller import to_json

with warnings.catch_warnings():
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    import imp

ERROR_LOG_LINE_TERMINATE = "\r"
ERROR_LOG_IDENT = "\u00a0"  # NO-BREAK SPACE U+00A0
_AWS_LAMBDA_LOG_FORMAT = LogFormat.from_str(os.environ.get("AWS_LAMBDA_LOG_FORMAT"))
_AWS_LAMBDA_LOG_LEVEL = _get_log_level_from_env_var(
    os.environ.get("AWS_LAMBDA_LOG_LEVEL")
)


def _get_handler(handler):
    try:
        (modname, fname) = handler.rsplit(".", 1)
    except ValueError as e:
        fault = FaultException(
            FaultException.MALFORMED_HANDLER_NAME,
            "Bad handler '{}': {}".format(handler, str(e)),
        )
        return make_fault_handler(fault)

    file_handle, pathname, desc = None, None, None
    try:
        # Recursively loading handler in nested directories
        for segment in modname.split("."):
            if pathname is not None:
                pathname = [pathname]
            file_handle, pathname, desc = imp.find_module(segment, pathname)
        if file_handle is None:
            module_type = desc[2]
            if module_type == imp.C_BUILTIN:
                fault = FaultException(
                    FaultException.BUILT_IN_MODULE_CONFLICT,
                    "Cannot use built-in module {} as a handler module".format(modname),
                )
                request_handler = make_fault_handler(fault)
                return request_handler
        m = imp.load_module(modname, file_handle, pathname, desc)
    except ImportError as e:
        fault = FaultException(
            FaultException.IMPORT_MODULE_ERROR,
            "Unable to import module '{}': {}".format(modname, str(e)),
        )
        request_handler = make_fault_handler(fault)
        return request_handler
    except SyntaxError as e:
        trace = ['  File "%s" Line %s\n    %s' % (e.filename, e.lineno, e.text)]
        fault = FaultException(
            FaultException.USER_CODE_SYNTAX_ERROR,
            "Syntax error in module '{}': {}".format(modname, str(e)),
            trace,
        )
        request_handler = make_fault_handler(fault)
        return request_handler
    finally:
        if file_handle is not None:
            file_handle.close()

    try:
        request_handler = getattr(m, fname)
    except AttributeError:
        fault = FaultException(
            FaultException.HANDLER_NOT_FOUND,
            "Handler '{}' missing on module '{}'".format(fname, modname),
            None,
        )
        request_handler = make_fault_handler(fault)
    return request_handler


def make_fault_handler(fault):
    def result(*args):
        raise fault

    return result


def make_error(error_message, error_type, stack_trace):
    result = {
        "errorMessage": error_message if error_message else "",
        "errorType": error_type if error_type else "",
        "stackTrace": stack_trace if stack_trace else [],
    }
    return result


def replace_line_indentation(line, indent_char, new_indent_char):
    ident_chars_count = 0
    for c in line:
        if c != indent_char:
            break
        ident_chars_count += 1
    return (new_indent_char * ident_chars_count) + line[ident_chars_count:]


if _AWS_LAMBDA_LOG_FORMAT == LogFormat.JSON:
    _ERROR_FRAME_TYPE = _JSON_FRAME_TYPES[logging.ERROR]
    _WARNING_FRAME_TYPE = _JSON_FRAME_TYPES[logging.WARNING]

    def log_error(error_result, log_sink):
        error_result = {
            "timestamp": time.strftime(
                _DATETIME_FORMAT, logging.Formatter.converter(time.time())
            ),
            "log_level": "ERROR",
            **error_result,
        }
        log_sink.log_error(
            [to_json(error_result)],
        )

else:
    _ERROR_FRAME_TYPE = _TEXT_FRAME_TYPES[logging.ERROR]
    _WARNING_FRAME_TYPE = _TEXT_FRAME_TYPES[logging.WARNING]

    def log_error(error_result, log_sink):
        error_description = "[ERROR]"

        error_result_type = error_result.get("errorType")
        if error_result_type:
            error_description += " " + error_result_type

        error_result_message = error_result.get("errorMessage")
        if error_result_message:
            if error_result_type:
                error_description += ":"
            error_description += " " + error_result_message

        error_message_lines = [error_description]

        stack_trace = error_result.get("stackTrace")
        if stack_trace is not None:
            error_message_lines += ["Traceback (most recent call last):"]
            for trace_element in stack_trace:
                if trace_element == "":
                    error_message_lines += [""]
                else:
                    for trace_line in trace_element.splitlines():
                        error_message_lines += [
                            replace_line_indentation(trace_line, " ", ERROR_LOG_IDENT)
                        ]

        log_sink.log_error(error_message_lines)


def handle_event_request(
    lambda_runtime_client,
    request_handler,
    invoke_id,
    event_body,
    content_type,
    client_context_json,
    cognito_identity_json,
    invoked_function_arn,
    epoch_deadline_time_in_ms,
    log_sink,
):
    error_result = None
    try:
        lambda_context = create_lambda_context(
            client_context_json,
            cognito_identity_json,
            epoch_deadline_time_in_ms,
            invoke_id,
            invoked_function_arn,
        )
        event = lambda_runtime_client.marshaller.unmarshal_request(
            event_body, content_type
        )
        response = request_handler(event, lambda_context)
        result, result_content_type = lambda_runtime_client.marshaller.marshal_response(
            response
        )
    except FaultException as e:
        xray_fault = make_xray_fault("LambdaValidationError", e.msg, os.getcwd(), [])
        error_result = make_error(e.msg, e.exception_type, e.trace)

    except Exception:
        etype, value, tb = sys.exc_info()
        tb_tuples = extract_traceback(tb)
        for i in range(len(tb_tuples)):
            if "/bootstrap.py" not in tb_tuples[i][0]:  # filename of the tb tuple
                tb_tuples = tb_tuples[i:]
                break

        xray_fault = make_xray_fault(etype.__name__, str(value), os.getcwd(), tb_tuples)
        error_result = make_error(
            str(value), etype.__name__, traceback.format_list(tb_tuples)
        )

    if error_result is not None:
        from lambda_literals import lambda_unhandled_exception_warning_message

        log_sink.log(lambda_unhandled_exception_warning_message, _WARNING_FRAME_TYPE)
        log_error(error_result, log_sink)
        lambda_runtime_client.post_invocation_error(
            invoke_id, to_json(error_result), to_json(xray_fault)
        )
    else:
        lambda_runtime_client.post_invocation_result(
            invoke_id, result, result_content_type
        )


def parse_json_header(header, name):
    try:
        return json.loads(header)
    except Exception as e:
        raise FaultException(
            FaultException.LAMBDA_CONTEXT_UNMARSHAL_ERROR,
            "Unable to parse {} JSON: {}".format(name, str(e)),
            None,
        )


def create_lambda_context(
    client_context_json,
    cognito_identity_json,
    epoch_deadline_time_in_ms,
    invoke_id,
    invoked_function_arn,
):
    client_context = None
    if client_context_json:
        client_context = parse_json_header(client_context_json, "Client Context")
    cognito_identity = None
    if cognito_identity_json:
        cognito_identity = parse_json_header(cognito_identity_json, "Cognito Identity")
    return LambdaContext(
        invoke_id,
        client_context,
        cognito_identity,
        epoch_deadline_time_in_ms,
        invoked_function_arn,
    )


def build_fault_result(exc_info, msg):
    etype, value, tb = exc_info
    tb_tuples = extract_traceback(tb)
    for i in range(len(tb_tuples)):
        if "/bootstrap.py" not in tb_tuples[i][0]:  # filename of the tb tuple
            tb_tuples = tb_tuples[i:]
            break

    return make_error(
        msg if msg else str(value), etype.__name__, traceback.format_list(tb_tuples)
    )


def make_xray_fault(ex_type, ex_msg, working_dir, tb_tuples):
    stack = []
    files = set()
    for t in tb_tuples:
        tb_file, tb_line, tb_method, tb_code = t
        tb_xray = {"label": tb_method, "path": tb_file, "line": tb_line}
        stack.append(tb_xray)
        files.add(tb_file)

    formatted_ex = {"message": ex_msg, "type": ex_type, "stack": stack}
    xray_fault = {
        "working_directory": working_dir,
        "exceptions": [formatted_ex],
        "paths": list(files),
    }
    return xray_fault


def extract_traceback(tb):
    return [
        (frame.filename, frame.lineno, frame.name, frame.line)
        for frame in traceback.extract_tb(tb)
    ]


class CognitoIdentity(object):
    __slots__ = ["cognito_identity_id", "cognito_identity_pool_id"]


class Client(object):
    __slots__ = [
        "installation_id",
        "app_title",
        "app_version_name",
        "app_version_code",
        "app_package_name",
    ]


class ClientContext(object):
    __slots__ = ["custom", "env", "client"]


def make_obj_from_dict(_class, _dict, fields=None):
    if _dict is None:
        return None
    obj = _class()
    set_obj_from_dict(obj, _dict)
    return obj


def set_obj_from_dict(obj, _dict, fields=None):
    if fields is None:
        fields = obj.__class__.__slots__
    for field in fields:
        setattr(obj, field, _dict.get(field, None))


class LambdaContext(object):
    def __init__(
        self,
        invoke_id,
        client_context,
        cognito_identity,
        epoch_deadline_time_in_ms,
        invoked_function_arn=None,
    ):
        self.aws_request_id = invoke_id
        self.log_group_name = os.environ.get("AWS_LAMBDA_LOG_GROUP_NAME")
        self.log_stream_name = os.environ.get("AWS_LAMBDA_LOG_STREAM_NAME")
        self.function_name = os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
        self.memory_limit_in_mb = os.environ.get("AWS_LAMBDA_FUNCTION_MEMORY_SIZE")
        self.function_version = os.environ.get("AWS_LAMBDA_FUNCTION_VERSION")
        self.invoked_function_arn = invoked_function_arn

        self.client_context = make_obj_from_dict(ClientContext, client_context)
        if self.client_context is not None:
            self.client_context.client = make_obj_from_dict(
                Client, self.client_context.client
            )

        self.identity = make_obj_from_dict(CognitoIdentity, {})
        if cognito_identity is not None:
            self.identity.cognito_identity_id = cognito_identity.get(
                "cognitoIdentityId"
            )
            self.identity.cognito_identity_pool_id = cognito_identity.get(
                "cognitoIdentityPoolId"
            )

        self._epoch_deadline_time_in_ms = epoch_deadline_time_in_ms

    def get_remaining_time_in_millis(self):
        epoch_now_in_ms = int(time.time() * 1000)
        delta_ms = self._epoch_deadline_time_in_ms - epoch_now_in_ms
        return delta_ms if delta_ms > 0 else 0

    def log(self, msg):
        for handler in logging.getLogger().handlers:
            if hasattr(handler, "log_sink"):
                handler.log_sink.log(str(msg))
                return
        sys.stdout.write(str(msg))


class LambdaLoggerHandler(logging.Handler):
    def __init__(self, log_sink):
        logging.Handler.__init__(self)
        self.log_sink = log_sink

    def emit(self, record):
        msg = self.format(record)
        self.log_sink.log(msg)


class LambdaLoggerHandlerWithFrameType(logging.Handler):
    def __init__(self, log_sink):
        super().__init__()
        self.log_sink = log_sink

    def emit(self, record):
        self.log_sink.log(
            self.format(record),
            frame_type=(
                getattr(record, "_frame_type", None)
                or _TEXT_FRAME_TYPES.get(_format_log_level(record))
            ),
        )


class LambdaLoggerFilter(logging.Filter):
    def filter(self, record):
        record.aws_request_id = _GLOBAL_AWS_REQUEST_ID or ""
        return True


class Unbuffered(object):
    def __init__(self, stream):
        self.stream = stream

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        pass

    def __getattr__(self, attr):
        return getattr(self.stream, attr)

    def write(self, msg):
        self.stream.write(msg)
        self.stream.flush()

    def writelines(self, msgs):
        self.stream.writelines(msgs)
        self.stream.flush()


class StandardLogSink(object):

    def __init__(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        pass

    def log(self, msg, frame_type=None):
        sys.stdout.write(msg)

    def log_error(self, message_lines):
        error_message = ERROR_LOG_LINE_TERMINATE.join(message_lines) + "\n"
        sys.stdout.write(error_message)


class FramedTelemetryLogSink(object):
    """
    FramedTelemetryLogSink implements the logging contract between runtimes and the platform. It implements a simple
    framing protocol so message boundaries can be determined. Each frame can be visualized as follows:
     <pre>
    {@code
    +----------------------+------------------------+---------------------+-----------------------+
    | Frame Type - 4 bytes | Length (len) - 4 bytes | Timestamp - 8 bytes | Message - 'len' bytes |
    +----------------------+------------------------+---------------------+-----------------------+
    }
    </pre>
    The first 4 bytes indicate the type of the frame - log frames have a type defined as the hex value 0xa55a0003. The
    second 4 bytes should indicate the message's length. The next 8 bytes should indicate the timestamp of the message.
    The next 'len' bytes contain the message. The byte order is big-endian.
    """

    def __init__(self, fd):
        self.fd = int(fd)

    def __enter__(self):
        self.file = os.fdopen(self.fd, "wb", 0)
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        self.file.close()

    def log(self, msg, frame_type=None):
        encoded_msg = msg.encode("utf8")

        timestamp = int(time.time_ns() / 1000)  # UNIX timestamp in microseconds
        log_msg = (
            (frame_type or _DEFAULT_FRAME_TYPE)
            + len(encoded_msg).to_bytes(4, "big")
            + timestamp.to_bytes(8, "big")
            + encoded_msg
        )
        self.file.write(log_msg)

    def log_error(self, message_lines):
        error_message = "\n".join(message_lines)
        self.log(
            error_message,
            frame_type=_ERROR_FRAME_TYPE,
        )


def is_pythonpath_set():
    return "PYTHONPATH" in os.environ


def get_opt_site_packages_directory():
    return "/opt/python/lib/python{}.{}/site-packages".format(
        sys.version_info.major, sys.version_info.minor
    )


def get_opt_python_directory():
    return "/opt/python"


# set default sys.path for discoverability
# precedence: /var/task -> /opt/python/lib/pythonN.N/site-packages -> /opt/python
def set_default_sys_path():
    if not is_pythonpath_set():
        sys.path.insert(0, get_opt_python_directory())
        sys.path.insert(0, get_opt_site_packages_directory())
    # '/var/task' is function author's working directory
    # we add it first in order to mimic the default behavior of populating sys.path and make modules under '/var/task'
    # discoverable - https://docs.python.org/3/library/sys.html#sys.path
    sys.path.insert(0, os.environ["LAMBDA_TASK_ROOT"])


def add_default_site_directories():
    # Set '/var/task as site directory so that we are able to load all customer .pth files
    site.addsitedir(os.environ["LAMBDA_TASK_ROOT"])
    if not is_pythonpath_set():
        site.addsitedir(get_opt_site_packages_directory())
        site.addsitedir(get_opt_python_directory())


def set_default_pythonpath():
    if not is_pythonpath_set():
        # keep consistent with documentation: https://docs.aws.amazon.com/lambda/latest/dg/lambda-environment-variables.html
        os.environ["PYTHONPATH"] = os.environ["LAMBDA_RUNTIME_DIR"]


def update_xray_env_variable(xray_trace_id):
    if xray_trace_id is not None:
        os.environ["_X_AMZN_TRACE_ID"] = xray_trace_id
    else:
        if "_X_AMZN_TRACE_ID" in os.environ:
            del os.environ["_X_AMZN_TRACE_ID"]


def create_log_sink():
    if "_LAMBDA_TELEMETRY_LOG_FD" in os.environ:
        fd = os.environ["_LAMBDA_TELEMETRY_LOG_FD"]
        del os.environ["_LAMBDA_TELEMETRY_LOG_FD"]
        return FramedTelemetryLogSink(fd)

    else:
        return StandardLogSink()


_GLOBAL_AWS_REQUEST_ID = None


def _setup_logging(log_format, log_level, log_sink):
    logging.Formatter.converter = time.gmtime
    logger = logging.getLogger()

    if log_format == LogFormat.JSON or log_level:
        logger_handler = LambdaLoggerHandlerWithFrameType(log_sink)
    else:
        logger_handler = LambdaLoggerHandler(log_sink)

    if log_format == LogFormat.JSON:
        logger_handler.setFormatter(JsonFormatter())
    else:
        logger_handler.setFormatter(
            logging.Formatter(
                "[%(levelname)s]\t%(asctime)s.%(msecs)03dZ\t%(aws_request_id)s\t%(message)s\n",
                "%Y-%m-%dT%H:%M:%S",
            )
        )

    if log_level in logging._nameToLevel:
        logger.setLevel(log_level)

    logger_handler.addFilter(LambdaLoggerFilter())
    logger.addHandler(logger_handler)


def main():
    sys.stdout = Unbuffered(sys.stdout)
    sys.stderr = Unbuffered(sys.stderr)

    with create_log_sink() as log_sink:
        lambda_runtime_api_addr = os.environ["AWS_LAMBDA_RUNTIME_API"]
        lambda_runtime_client = LambdaRuntimeClient(lambda_runtime_api_addr)

        try:
            _setup_logging(_AWS_LAMBDA_LOG_FORMAT, _AWS_LAMBDA_LOG_LEVEL, log_sink)

            global _GLOBAL_AWS_REQUEST_ID

            set_default_sys_path()
            add_default_site_directories()
            set_default_pythonpath()

            handler = os.environ["_HANDLER"]
            request_handler = _get_handler(handler)
        except Exception:
            error_result = build_fault_result(sys.exc_info(), None)

            log_error(error_result, log_sink)
            lambda_runtime_client.post_init_error(to_json(error_result))

            sys.exit(1)

        while True:
            event_request = lambda_runtime_client.wait_next_invocation()

            _GLOBAL_AWS_REQUEST_ID = event_request.invoke_id

            update_xray_env_variable(event_request.x_amzn_trace_id)

            handle_event_request(
                lambda_runtime_client,
                request_handler,
                event_request.invoke_id,
                event_request.event_body,
                event_request.content_type,
                event_request.client_context,
                event_request.cognito_identity,
                event_request.invoked_function_arn,
                event_request.deadline_time_in_ms,
                log_sink,
            )


if __name__ == "__main__":
    main()
