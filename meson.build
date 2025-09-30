project('secure-exec-server', 'c',
        version : '0.1',
        default_options : ['warning_level=3'])

dep_glib = dependency('glib-2.0')
dep_libcrypto = dependency('libcrypto', version: '>=3')
exe = executable('ses',
                 'src/secure-exec-server.c',
                 'src/ses_crypto.c',
                 'src/ses_utils.c',
                 dependencies: [dep_glib, dep_libcrypto],
                 install : true)

test('basic', find_program('test/test_basic'), is_parallel: false)
test('shutdown', find_program('test/test_shutdown'), is_parallel: false)
test('auth_invalid_input', find_program('test/test_auth_invalid_input'), is_parallel: false)
test('auth_signature', find_program('test/test_auth_signature'), is_parallel: false)
test('keyusage', find_program('test/test_keyusage'), is_parallel: false)
test('child_process', find_program('test/test_child_process'), is_parallel: false)
test('child_parallel', find_program('test/test_child_parallel'), is_parallel: false)
