#pragma once



extern "C" {
  typedef struct PGconn PGconn;
  typedef struct PGresult PGresult;

  typedef enum ExecStatusType {
    PGRES_EMPTY_QUERY = 0,
    PGRES_COMMAND_OK,
    PGRES_TUPLES_OK,
    PGRES_SINGLE_TUPLE,
    PGRES_FATAL_ERROR
  } ExecStatusType;

  
  PGconn* PQconnectdb(const char* conninfo);
  void PQfinish(PGconn*);
  int PQstatus(PGconn*);
#define CONNECTION_OK 0

  
  PGresult* PQexec(PGconn*, const char* query);
  PGresult* PQexecParams(PGconn*, const char* cmd, int nParams, const void*, const char* const *paramValues, const int*, const int*, int resultFormat);
  void PQclear(PGresult*);

  
  ExecStatusType PQresultStatus(PGresult*);
  const char* PQresultErrorMessage(PGresult*);
  const char* PQresStatus(ExecStatusType);
  const char* PQresultErrorField(PGresult*, int fieldcode);
  int PQnfields(PGresult*);
  int PQntuples(PGresult*);
  char* PQgetvalue(PGresult*, int tup_num, int field_num);
  int PQgetisnull(PGresult*, int tup_num, int field_num);
  char* PQcmdTuples(PGresult*);
  const char* PQfname(PGresult*, int field_num);

  
  static const int PG_DIAG_SQLSTATE = 1;

  
  void fake_pg_clear_queue();
  void fake_pg_set_connect_ok(int ok);
  void fake_pg_queue_null();
  void fake_pg_queue_response(ExecStatusType status, const char* errmsg, const char* sqlstate, const char* cols_csv, const char* rows_csv, const char* cmd_tuples);
}
