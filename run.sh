#!/bin/bash

# Stream Cipher Demo Runner
# Компилира, изпълнява и почиства Java файловете

set -e  # Exit on error

echo "================================="
echo "Stream Cipher Demo Runner"
echo "================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SRC_DIR="$SCRIPT_DIR/src"

# Function to compile
compile() {
    echo -e "${BLUE}[1/3] Компилиране на Java файлове...${NC}"
    cd "$SRC_DIR"
    javac *.java
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Компилацията завърши успешно${NC}"
        echo ""
    else
        echo -e "${RED}✗ Грешка при компилация${NC}"
        exit 1
    fi
}

# Function to run programs
run_programs() {
    echo -e "${BLUE}[2/3] Изпълнение на програмите...${NC}"
    echo ""
    
    # Menu for user selection
    echo "Изберете програма за изпълнение:"
    echo "  1) StreamCipherDemo          - Демонстрации и примери"
    echo "  2) StreamCipherBenchmark     - Performance тестове"
    echo "  3) SecurityAnalysis          - Security анализи"
    echo "  4) AdvancedBenchmark         - Сравнение с Bouncy Castle (изисква библиотека)"
    echo "  5) Всички програми (1, 2, 3) - Последователно изпълнение"
    echo "  6) Изход"
    echo ""
    
    read -p "Избор (1-6): " choice
    echo ""
    
    case $choice in
        1)
            echo -e "${YELLOW}═══ StreamCipherDemo ═══${NC}"
            java StreamCipherDemo
            ;;
        2)
            echo -e "${YELLOW}═══ StreamCipherBenchmark ═══${NC}"
            java StreamCipherBenchmark
            ;;
        3)
            echo -e "${YELLOW}═══ SecurityAnalysis ═══${NC}"
            java SecurityAnalysis
            ;;
        4)
            echo -e "${YELLOW}═══ AdvancedBenchmark (с Bouncy Castle) ═══${NC}"
            if [ -f "../bcprov-jdk15on-1.70.jar" ]; then
                java -cp ".:../bcprov-jdk15on-1.70.jar" AdvancedBenchmark
            else
                echo -e "${RED}✗ bcprov-jdk15on-1.70.jar не е намерена в родителската директория${NC}"
                echo "Свалете я от: https://www.bouncycastle.org/latest_releases.html"
                exit 1
            fi
            ;;
        5)
            echo -e "${YELLOW}═══ StreamCipherDemo ═══${NC}"
            java StreamCipherDemo
            echo ""
            echo -e "${YELLOW}═══ StreamCipherBenchmark ═══${NC}"
            java StreamCipherBenchmark
            echo ""
            echo -e "${YELLOW}═══ SecurityAnalysis ═══${NC}"
            java SecurityAnalysis
            ;;
        6)
            echo "Изход без изпълнение."
            ;;
        *)
            echo -e "${RED}✗ Невалиден избор${NC}"
            exit 1
            ;;
    esac
    
    echo ""
}

# Function to clean
clean() {
    echo -e "${BLUE}[3/3] Почистване на .class файлове...${NC}"
    cd "$SRC_DIR"
    rm -f *.class
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Почистването завърши успешно${NC}"
    else
        echo -e "${RED}✗ Грешка при почистване${NC}"
        exit 1
    fi
}

# Main execution
compile
run_programs
clean

echo ""
echo -e "${GREEN}=================================${NC}"
echo -e "${GREEN}Готово!${NC}"
echo -e "${GREEN}=================================${NC}"
