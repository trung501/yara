#include <cjson/cJSON.h>
#include <wchar.h>
#include <stdlib.h>
#include <wchar.h>
#include <yara/types.h>

#define SIZE 100

char* wchar2char(const wchar_t* name)
{
  char* value = (char*) malloc(SIZE);

  size_t narrowCharLength;

  wcstombs_s(&narrowCharLength, value, (size_t) SIZE, name, (size_t) SIZE);
  return value;
}

char* Convert2Json(DetectResult detectRes)
{

  cJSON* detectResJson = cJSON_CreateObject();
  char* filename = (char*) malloc(SIZE);
  filename = wchar2char(detectRes.file_name);

  cJSON_AddStringToObject(detectResJson, "file_name", filename);
  int numdetect = detectRes.size;
  cJSON_AddItemToObject(
      detectResJson, "number_ruleMatch", cJSON_CreateNumber(numdetect));

  cJSON* RuleMatchJson = cJSON_CreateArray();

  for (size_t i = 0; i < numdetect; i++)
  {  // for -> rule_matchs
    const RuleMatch* ruleItem = detectRes.rule_matchs[i];
    cJSON* ruleItemJson = cJSON_CreateObject();  // json

    cJSON_AddStringToObject(ruleItemJson, "rule_name", ruleItem->rule_name);

    Metadata* metadata = ruleItem->meta_data;

    cJSON* metaDataJson = cJSON_CreateObject();  // json

    cJSON_AddItemToObject(
        metaDataJson, "number_metaData", cJSON_CreateNumber(metadata->size));

    int numMeta = metadata->size;

    cJSON* keyJson = cJSON_CreateArray();
    cJSON* valueJson = cJSON_CreateArray();

    for (size_t j = 0; j < numMeta; j++)
    {  // for  -> key array

      cJSON* itemKeyJson = cJSON_CreateObject();    // json
      cJSON* itemValueJson = cJSON_CreateObject();  // json

      cJSON_AddItemToArray(keyJson, cJSON_CreateString(metadata->key[j]));
      cJSON_AddItemToArray(valueJson, cJSON_CreateString(metadata->value[j]));
    }

    cJSON_AddItemToObject(metaDataJson, "key", keyJson);
    cJSON_AddItemToObject(metaDataJson, "value", valueJson);

    cJSON_AddItemToObject(ruleItemJson, "meta_data", metaDataJson);

    cJSON_AddItemToArray(RuleMatchJson, ruleItemJson);
  }

  cJSON_AddItemToObject(detectResJson, "rule_match", RuleMatchJson);


  char* jsonString = cJSON_Print(detectResJson);
  return jsonString;
}