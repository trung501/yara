// testrundll.cpp : This file contains the 'main' function. Program execution
// begins and ends there.
//
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <cstdlib>
#include <iostream>
using namespace std;

typedef struct MetaData
{
  char** key;
  char** value;
  int size;
} Metadata;

typedef struct RuleMatch
{
  char* rule_name;
  Metadata* meta_data;
} RuleMatch;

typedef struct DetectResult
{
  wchar_t* file_name;
  int size;
  RuleMatch** rule_matchs;
} DetectResult;


typedef int (
    __cdecl* init_function)(const wchar_t* pathRule);
typedef const DetectResult* (
    __cdecl* detect)(const wchar_t* pathFileScan);
typedef void(__cdecl* free_detect_result)(DetectResult* dr);
typedef void(
    __cdecl* destroy)();

int main(int agrc, const char** argv)
{
      HINSTANCE hinstLib;
      init_function InitFunction;
      detect Detect;
      free_detect_result FreeDetectResult;
      destroy Destroy;

      BOOL fFreeResult, fRunTimeLinkSuccess = FALSE;
    hinstLib = LoadLibrary(TEXT("yara32.dll"));

  if (hinstLib != NULL)

  {
    wchar_t rule_path[256];
    wchar_t path_scan[256];
    wprintf(L"Nhap duong dan file rule: ");
    wscanf(L"%255ls", rule_path);
    wprintf(L"Nhap PID hoac duong dan file can scan: ");
    wscanf(L"%255ls", path_scan);

    int result;
    
    InitFunction = (init_function) GetProcAddress(hinstLib, "init_function");
    Detect = (detect) GetProcAddress(hinstLib, "detect");
    Destroy = (destroy) GetProcAddress(hinstLib, "destroy");
    FreeDetectResult = (free_detect_result) GetProcAddress(hinstLib, "free_detect_result");

    // If the function address is valid, call the function.
    if (NULL != InitFunction && NULL != Detect && NULL != Destroy) {
        fRunTimeLinkSuccess = TRUE;
        result = InitFunction(rule_path);
        if (result != -1)
        {
          const DetectResult* dr1 = Detect(path_scan);
          if (dr1 != NULL)
          {
                wprintf(L"File(PID) scan: %s \n", dr1->file_name);
                wprintf(L"Number of match rule: %d \n", dr1->size);
                wprintf(L"Match rule:\n");
                for (int i = 0; i < dr1->size; i++)
                {
                  RuleMatch* rm = dr1->rule_matchs[i];
                  printf("\tRuleName:  %s \n", rm->rule_name);
                  printf("\tMetadata:\n");
                  MetaData* md = rm->meta_data;
                  for (int j = 0; j < md->size; j++)
                  {
                    printf("\t\t %s: %s\n", md->key[j], md->value[j]);
                  }
                }
                wprintf(L"-----------------------------------\n");
                FreeDetectResult((DetectResult*) dr1);
          }         
        

        }
       
        //DOn dep
        Destroy();
    }
    
    fFreeResult = FreeLibrary(hinstLib);
  }

  // If unable to call the DLL function, use an alternative.
  if (!fRunTimeLinkSuccess)
    printf("Message printed from executable\n");

  return 0;
}
