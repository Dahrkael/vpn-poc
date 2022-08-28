#pragma once

#define CLEAR(structure) memset(&structure, 0, sizeof(structure));

typedef enum {
   false = 0,
   true = 1
} bool;
