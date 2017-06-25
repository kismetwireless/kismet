/* test harness for Kismet json parser
 *
 * # Optionally, turn on debugging the JSON parser by uncommenting
 * the #define JSON_DEBUG line in kismet_json.c
 *
 * # configure kismet with asan
 * ./configure --enable-asan
 *
 * # build kismet
 * make
 *
 * # build test harness
 * g++ -o json_parser_test.o -c json_parser_test.cc -fsanitize=address
 * g++ -o json_parser_test json_parser_test.o kismet_json.o -lasan
 *
 * echo some json | ./json_parser_test
 *
 */

#include "config.h"

#include <string>
#include <iostream>

#include "kismet_json.h"

int main(void) {
    string jsonblob;
    string line;
    struct JSON_value *json;
    string err;

    while (std::getline(std::cin, line)) {
        jsonblob += line;
    }

    json = JSON_parse(jsonblob, err);

    if (json == NULL || err.length() != 0) {
        fprintf(stderr, "Could not parse json: %s\n", err.c_str());

        if (json != NULL)
            JSON_delete(json);

        exit(1);
    }

    JSON_dump(json, "", 0);


    JSON_delete(json);

}

