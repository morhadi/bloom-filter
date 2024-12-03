#include <bitset>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

using namespace std;

/*
Polynomial Rolling Hashing Function 
is a hash function that uses only multiplications and additions.

Hash(s) = ( s[0] + s[1]*p + s[2]*p^2 + ... ) % m

Where:
- s is the input string
- p is a prime number, usually a small value like 31
- m is a large prime number used to take the modulus
*/
unsigned long long polynomial_hash(const string &s, long long p, long long m)
{
    unsigned long long hash = 0;
    long long p_pow = 1;
    for (char c : s)
    {
        hash = (hash + (c - 'a' + 1) * p_pow) % m;
        p_pow = (p_pow * p) % m;
    }
    return hash;
}

/*
DJB2
This algorithm (k=33) was first reported by Dan Bernstein many years ago in comp.lang.c. 
Another version of this algorithm (now favored by Bernstein) uses XOR: 

hash(i) = hash(i - 1) * 33 ^ str[i]; 

The magic of number 33 (why it works better than many other constants, prime or not) has never been adequately explained.
This function uses bitwise operations and arithmetic to compute a hash value efficiently.

Hash(s) = 5381 * 33 + s[i]
*/
unsigned long long djb2(const string &s)
{
    unsigned long long hash = 5381;
    for (char c : s)
    {
        hash = ((hash << 5) + hash) + c;  // hash * 33 + c
    }
    return hash;
}

/*
SDBM
This algorithm was created for sdbm (a public-domain reimplementation of ndbm)
database library.
It was found to do well in scrambling bits, causing better distribution of the keys
and fewer splits.
It also happens to be a good general hashing function with good distribution.

Hash(s) = hash(i - 1) * 65599 + str[i]
*/
unsigned long long sdbm(const string &s)
{
    unsigned long long hash = 0;
    for (char c : s)
    {
        hash = c + (hash << 6) + (hash << 16) - hash;
    }
    return hash;
}

class BloomFilter
{
private:
    long long p = 31;
    long long m = 1e9 + 9;  // Using 1e9 + 9 for practical purposes
    long long size;
    string filename;
    bitset<1000001> bits;  // Correctly sized bitset

public:
    BloomFilter(string filename) : size(0), filename(filename), bits(0)
    {
        ifstream file(filename);
        if (file.is_open())
        {
            string line;
            while (getline(file, line))
            {
                add(line);
                size++;
            }
            file.close();
        }
        else
        {
            cerr << "Unable to open file: " << filename << endl;
        }
    }

    void add(const string &s)
    {
        auto hash = polynomial_hash(s, p, m);
        auto hash2 = djb2(s) % m;
        auto hash3 = sdbm(s) % m;
        bits.set(hash % bits.size());
        bits.set(hash2 % bits.size());
        bits.set(hash3 % bits.size());
    }

    bool contains(const string &s)
    {
        auto hash = polynomial_hash(s, p, m);
        auto hash2 = djb2(s) % m;
        auto hash3 = sdbm(s) % m;

        return bits.test(hash % bits.size()) && bits.test(hash2 % bits.size()) && bits.test(hash3 % bits.size());
    }

    void test(const string &filename)
    {
        int positives = 0;
        int negatives = 0;
        vector<string> maliciousUrls;  // Vector to hold malicious URLs
        ifstream file(filename);
        if (file.is_open())
        {
            string line;
            while (getline(file, line))
            {
                bool result = contains(line);
                cout << "Checking " << line << " : " << (result ? "possibly malicious" : "not malicious") << endl;
                positives += result;
                negatives += !result;
                if (result)
                {
                    maliciousUrls.push_back(line);  // Store malicious URLs
                }
            }
            file.close();
        }
        else
        {
            cerr << "Unable to open file: " << filename << endl;
        }

        cout << "Total Positives: " << positives << endl;
        cout << "Total Negatives: " << negatives << endl;

        // Print all URLs that were found to be malicious
        if (!maliciousUrls.empty())
        {
            cout << "\nMalicious URLs:\n";
            for (const string &url : maliciousUrls)
            {
                cout << url << endl;
            }
        }
        else
        {
            cout << "\nNo malicious URLs found.\n";
        }
    }

    bitset<1000001> get_bits() { return bits; }
};

int main()
{
    BloomFilter bf("malicious.csv");

    // Minimal interactive TUI
    while (true)
    {
        cout << "\n--- Bloom Filter Menu ---\n";
        cout << "Bitset size: " << bf.get_bits().size() << "\n";
        cout << "Hash functions used: Polynomial Rolling, DJB2, SDBM\n";
        cout << "1. Test a file\n";
        cout << "2. Test a website string\n";
        cout << "3. Exit\n";
        cout << "Enter your choice: ";

        int choice;
        if (!(cin >> choice))
        {
            cin.clear();                                          // clear the error flag
            cin.ignore(numeric_limits<streamsize>::max(), '\n');  // discard invalid input
            cout << "Invalid input. Please enter a number between 1 and 3.\n";
            continue;
        }

        if (choice == 1)
        {
            string test_filename;
            cout << "Enter the file name to test: ";
            cin >> test_filename;
            bf.test(test_filename);
        }
        else if (choice == 2)
        {
            string website;
            cout << "Enter the website URL to test: ";
            cin >> website;
            bool result = bf.contains(website);
            cout << "The website " << website << " is " << (result ? "possibly malicious." : "not malicious.") << endl;
        }
        else if (choice == 3)
        {
            break;
        }
        else
        {
            cout << "Invalid choice. Please enter a number between 1 and 3.\n";
        }
    }

    return 0;
}
