# Лабораторная работа: Статический и динамический анализ (C++)

Уязвимый HTTP-сервер управления документами на C++ для курса  
«Проектирование и разработка в защищённом исполнении».

## Требования

- CMake ≥ 3.14
- Компилятор с поддержкой C++17 (g++ / clang++)
- cpp-httplib (файл `httplib.h` уже должен лежать в корне проекта)

## Сборка и запуск

```bash
mkdir build && cd build
cmake ..
make
./server
```

Сервер слушает порт **8080**.

## Основные уязвимости (для поиска)

| Уязвимость                  | CWE     | Файл(ы)              |
|----------------------------|---------|----------------------|
| Hardcoded secrets          | CWE-798 | config.h             |
| Buffer Overflow (strcpy)   | CWE-120 | auth.cpp             |
| Command Injection          | CWE-78  | utils.cpp            |
| Path Traversal             | CWE-22  | utils.cpp, main.cpp  |
| Format String              | CWE-134 | documents.cpp        |
| IDOR / Broken Access Control | CWE-639 | documents.cpp, main.cpp |
| Weak cryptography          | CWE-327 | utils.cpp            |
| Dangerous functions        | CWE-676 | auth.cpp, utils.cpp  |

## Рекомендуемые инструменты SAST

```bash
cppcheck --enable=all --inconclusive --std=c++17 .
flawfinder .
scan-build make          # Clang Static Analyzer
semgrep --config=p/c --config=p/cpp .
```

## Примеры динамических атак

```bash
# Логин
curl -X POST "http://localhost:8080/login" -d "username=admin&password=admin123" -c cookies.txt

# IDOR
curl "http://localhost:8080/document/1"

# Path Traversal
curl -X POST "http://localhost:8080/upload" -d "filename=../../tmp/pwned.txt&content=hacked"

# Command Injection
curl "http://localhost:8080/admin/cmd?cmd=id"

# Format String
curl "http://localhost:8080/search?q=%25s%25s%25n"

# Arbitrary file read
curl "http://localhost:8080/read?path=../../../etc/passwd"
```

## Задание студенту

1. Провести статический анализ (≥ 2 инструмента).
2. Найти и задокументировать уязвимости.
3. Исправить код.
4. Провести динамическое тестирование.
5. Сравнить результаты SAST и DAST.
6. Подготовить отчёт.
