#include "libpq-fe.h"
#include <string>
#include <queue>
#include <vector>
#include <cstring>
#include <mutex>
#include <optional>

struct FakeConn { int ok; };

struct FakeResult {
  ExecStatusType status;
  std::string errmsg;
  std::string sqlstate;
  std::vector<std::string> columns;
  
  std::vector<std::vector<std::optional<std::string>>> rows;
  std::string cmdtuples;
};

struct QueueItem { bool is_null; FakeResult res; };

static std::queue<QueueItem> g_queue;
static std::mutex g_mu;
static int g_connect_ok = 1;

extern "C" {

PGconn* PQconnectdb(const char* conninfo) {
  (void)conninfo;
  FakeConn* c = new FakeConn(); c->ok = g_connect_ok; return reinterpret_cast<PGconn*>(c);
}

void PQfinish(PGconn* c) { delete reinterpret_cast<FakeConn*>(c); }

int PQstatus(PGconn* c) { (void)c; return g_connect_ok ? CONNECTION_OK : 1; }

PGresult* PQexec(PGconn* c, const char* query) {
  (void)c; (void)query;
  std::lock_guard<std::mutex> lk(g_mu);
  if (g_queue.empty()) return nullptr;
  QueueItem item = g_queue.front(); g_queue.pop();
  if (item.is_null) return nullptr;
  FakeResult* out = new FakeResult(std::move(item.res));
  return reinterpret_cast<PGresult*>(out);
}

PGresult* PQexecParams(PGconn* c, const char* cmd, int nParams, const void*, const char* const *paramValues, const int*, const int*, int) {
  (void)c; (void)cmd; (void)nParams; (void)paramValues;
  std::lock_guard<std::mutex> lk(g_mu);
  if (g_queue.empty()) return nullptr;
  QueueItem item = g_queue.front(); g_queue.pop();
  if (item.is_null) return nullptr;
  FakeResult* out = new FakeResult(std::move(item.res));
  return reinterpret_cast<PGresult*>(out);
}

void PQclear(PGresult* r) { delete reinterpret_cast<FakeResult*>(r); }

ExecStatusType PQresultStatus(PGresult* r) { return reinterpret_cast<FakeResult*>(r)->status; }

const char* PQresultErrorMessage(PGresult* r) { return reinterpret_cast<FakeResult*>(r)->errmsg.c_str(); }

const char* PQresStatus(ExecStatusType st) {
  switch (st) {
    case PGRES_COMMAND_OK: return "PGRES_COMMAND_OK";
    case PGRES_TUPLES_OK: return "PGRES_TUPLES_OK";
    default: return "PGRES_OTHER";
  }
}

const char* PQresultErrorField(PGresult* r, int) { return reinterpret_cast<FakeResult*>(r)->sqlstate.c_str(); }

int PQnfields(PGresult* r) { return (int)reinterpret_cast<FakeResult*>(r)->columns.size(); }

int PQntuples(PGresult* r) { return (int)reinterpret_cast<FakeResult*>(r)->rows.size(); }

char* PQgetvalue(PGresult* r, int tup, int field) {
  auto& fr = *reinterpret_cast<FakeResult*>(r);
  if (tup < 0 || tup >= (int)fr.rows.size()) return nullptr;
  if (field < 0 || field >= (int)fr.columns.size()) return nullptr;
  const std::optional<std::string>& opt = fr.rows[tup][field];
  if (!opt.has_value()) return nullptr; 
  return const_cast<char*>(opt->c_str());
}

int PQgetisnull(PGresult* r, int tup, int field) {
  auto& fr = *reinterpret_cast<FakeResult*>(r);
  if (tup < 0 || tup >= (int)fr.rows.size()) return 1;
  if (field < 0 || field >= (int)fr.columns.size()) return 1;
  return fr.rows[tup][field].has_value() ? 0 : 1;
}

char* PQcmdTuples(PGresult* r) {
  auto& fr = *reinterpret_cast<FakeResult*>(r);
  return const_cast<char*>(fr.cmdtuples.c_str());
}

const char* PQfname(PGresult* r, int field) {
  auto& fr = *reinterpret_cast<FakeResult*>(r);
  if (field < 0 || field >= (int)fr.columns.size()) return nullptr;
  return fr.columns[field].c_str();
}

void fake_pg_clear_queue() { std::lock_guard<std::mutex> lk(g_mu); while(!g_queue.empty()) g_queue.pop(); }
void fake_pg_set_connect_ok(int ok) { g_connect_ok = ok; }
void fake_pg_queue_null() { std::lock_guard<std::mutex> lk(g_mu); g_queue.push(QueueItem{true, FakeResult()}); }
void fake_pg_queue_response(ExecStatusType status, const char* errmsg, const char* sqlstate, const char* cols_csv, const char* rows_csv, const char* cmd_tuples) {
  std::lock_guard<std::mutex> lk(g_mu);
  FakeResult fr;
  fr.status = status;
  fr.errmsg = errmsg ? errmsg : std::string();
  fr.sqlstate = sqlstate ? sqlstate : std::string();
  fr.cmdtuples = cmd_tuples ? cmd_tuples : std::string();
  
  if (cols_csv && cols_csv[0]) {
    std::string cols(cols_csv);
    size_t pos = 0;
    while (true) {
      size_t p = cols.find(',', pos);
      if (p == std::string::npos) { fr.columns.push_back(cols.substr(pos)); break; }
      fr.columns.push_back(cols.substr(pos, p-pos)); pos = p+1;
    }
  }
  
  if (rows_csv && rows_csv[0]) {
    std::string rows(rows_csv);
    size_t pos = 0;
    while (pos < rows.size()) {
      size_t p = rows.find(';', pos);
      std::string row = (p==std::string::npos) ? rows.substr(pos) : rows.substr(pos, p-pos);
      std::vector<std::optional<std::string>> cells;
      size_t cpos = 0;
      while (true) {
        size_t cp = row.find(',', cpos);
        std::string token = (cp == std::string::npos) ? row.substr(cpos) : row.substr(cpos, cp-cpos);
        if (token == "<NULL>") cells.push_back(std::nullopt);
        else cells.push_back(std::optional<std::string>(token));
        if (cp == std::string::npos) break;
        cpos = cp+1;
      }
      fr.rows.push_back(std::move(cells));
      if (p==std::string::npos) break; pos = p+1;
    }
  }
  g_queue.push(QueueItem{false, std::move(fr)});
}

} 
