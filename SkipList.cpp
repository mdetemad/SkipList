/**************************************************************************\
*   Author:   Mohammad Etemad                                              *
*   Date:     May 2015        (Version 1)                                  *
*                                                                          *
*   This is an implementation of an Authenticated Skip List.               *
*   It is a dynamic data structure that supports adding/deleting           *
*       new data blocks into the list.                                     *
*   Given a text file, it reads the file in blocks of the specified size,  *
*   builds the tree and produces and verifies the membership proofs.       *
*                                                                          *
\**************************************************************************/

#include <algorithm>
#include <vector>
#include <string>
#include <numeric>
#include <math.h>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <iostream>
#include <openssl/sha.h>

using namespace std;
typedef unsigned char byte;
string strResult;

struct Node
{
    int level;
    string key, value, hashValue;
    Node *left, *right, *parent;
};

class SkipList
{
    Node* root;
    int blockSize, blockNo, levels;
	const int HASHSIZE = 2 * SHA256_DIGEST_LENGTH;

    public:
    SkipList(int bSize) : blockSize(bSize)
    {
        blockNo = -1;
        srand(time(NULL));
        levels = 20;    // This is temporary, it should be computed/guessed.

        // Initiate the skiplist
        root = new Node();
        root->level = levels;
        root->parent = nullptr;
        root->key = "00000000000000000000000000000000";
        root->value = root->key;

        Node* left = new Node();
        left->left = left->right = nullptr;
        left->parent = root;
        left->level = 0;
        left->key = "00000000000000000000000000000000";
        left->value = left->key;
        left->hashValue = SHA256(left->key);

        Node* right = new Node();
        right->left = right->right = nullptr;
        right->parent = root;
        right->level = 0;
        right->key = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
        right->value = right->key;
        right->hashValue = SHA256(right->key);

        root->right = right;
        root->left = left;
        root->hashValue = SHA256(left->hashValue + right->hashValue);
}

    string SHA256(const string strIn)
    {
        byte hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, strIn.c_str(), strIn.size());
        SHA256_Final(hash, &sha256);
        stringstream ss;
        for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
            ss << hex << setw(2) << setfill('0') << (int)hash[i];
        return ss.str();
    }

    // This function receives the file name,
    // reads the text in chunks of the given size, and
    // builds the skiplist accordingly.
    bool Build(const char* fileName)
    {
        ifstream inFile(fileName);
        if(!inFile.good())
            return false;

        // Now, read the file block by block of the given size.
        // And, add all blocks into a list.
        char block[blockSize + 1];
        block[blockSize] = '\0';
        while (!inFile.eof())
        {
            inFile.read(block, blockSize);
            if(!inFile.gcount())
                continue;
            string key = SHA256(to_string(++blockNo));
            Insert(key, block);
            cout << root->key << "\n\t" << root->hashValue << endl;
            cout << root->right->key << "\n\t" << root->right->hashValue << endl;
        }
        
        return true;
    }

    // This function inserts a new block with the given key at a random level.
    void Insert(const string key, const string block)
    {
        Node* newNode = new Node();
        int level = rand() % levels;  // Assign a random level
        //cout << "New level: " << level << endl;
        newNode->level = level;
		newNode->key = key;
		newNode->value = block;
		newNode->hashValue = SHA256(block);
		newNode->left = newNode->right = newNode->parent = nullptr;

        // Go to the place of the node.
        Node *ptr = root, *temp = nullptr;
		while (ptr->right)
		{
			if (key > ptr->right->key)
            {
                //cout << "Right." << endl;
				ptr = ptr->right;
            }else
			{
                //cout << "Left." << endl;
				if (ptr->left)
					ptr = ptr->left;
				else
                    break;
			}
		}

        //cout << "Level: " << level << "\tLevel: " << ptr->level << "\tKey: " << ptr->key << endl;
		// If level is zero, at to the right.
		if (!level)
		{
			newNode->parent = ptr;
			newNode->right = ptr->right;
			ptr->right = newNode;
			if (newNode->right)
			{
				newNode->right->parent = newNode;
				newNode->hashValue = SHA256(newNode->value + newNode->right->hashValue);
			}else
				newNode->hashValue = SHA256(newNode->value);

			// Update hash values upward.
            UpdateHash(ptr);
		}
		else
		{
			ptr = ptr->parent;
            //cout << "Now at level 1: " << ptr->level << "\t" << ptr->key << endl;
			while (ptr)
			{
				if (ptr->level < level)
				{
					if (ptr->right->key > key)
					{
						ptr->parent->right = ptr->left;
						ptr->left->parent = ptr->parent;
						ptr->left = newNode;
						newNode->parent = ptr;
						newNode = ptr;
						ptr->key = newNode->key;

						// Now update hashes:
                        ptr = ptr->parent;
						ptr->hashValue = SHA256(ptr->left->hashValue + ptr->right->hashValue);
						newNode->hashValue = SHA256(newNode->left->hashValue + newNode->right->hashValue);
					}
					else
					{
						ptr->hashValue = SHA256(ptr->left->hashValue + ptr->right->hashValue);
                        ptr = ptr->parent;
					}
				}
				else if (ptr->level > level)
				{
                    temp = new Node();
                    if(ptr->key == root->key)
                    {
                        temp->key = ptr->key;
                        temp->parent = ptr;
                        temp->left = ptr->left;
                        temp->right = newNode;
                        ptr->left->parent = temp;
                        ptr->left = temp;
                        newNode->parent = temp;
                    }else
                    {
                        temp->key = ptr->right->key;
                        temp->parent = ptr;
                        temp->left = ptr->right;
                        temp->right = newNode;
                        ptr->right->parent = temp;
                        ptr->right = temp;
                        newNode->parent = temp;
                    }

                    UpdateHash(temp);
                    return;
                }
                else
                {
                    //cout << "Levels == " << ptr->level << "\t" << ptr->key << endl;
                    temp = new Node();
                    if(ptr->key == root->key)
                    {
                        temp->key = newNode->key;
                        temp->parent = ptr;
                        temp->left = newNode;
                        temp->right = ptr->right;
                        ptr->right->parent = temp;
                        ptr->right = temp;
                        newNode->parent = temp;
                    }else
                    {
                        temp->key = ptr->right->key;
                        temp->parent = ptr;
                        temp->left = ptr->right;
                        temp->right = newNode;
                        ptr->right->parent = temp;
                        ptr->right = temp;
                        newNode->parent = temp;
                    }

                    UpdateHash(temp);
                    return;

                }
			}
		}
    }

    // Recursively go upward and update all hash values on the way.
    void UpdateHash(Node* leftN)
    {
        leftN->hashValue = SHA256(leftN->left->hashValue + leftN->right->hashValue);
        Node *parentN = leftN->parent, *rightN = nullptr;
        while(parentN)
        {
            if(parentN->left == leftN)
                rightN = parentN->right;
            else
            {
                rightN = leftN;
                leftN = parentN->left;
            }

            parentN->hashValue = SHA256(leftN->hashValue + rightN->hashValue);
            leftN = parentN;
            parentN = parentN->parent;
        }
    }

    // Print the leaf values for test purposes.
    void PrintList()
    {
        Traverse(root);
        cout << endl;
    }

    void Traverse(const Node* tree)
    {
		if (!tree)
			return;
        if(!tree->left)
        {
            cout << tree->key << "\n\t" << tree->hashValue << endl;
			Traverse(tree->right);
			return;
        }

        Traverse(tree->left);
        Traverse(tree->right);
    }

    void Traverse2(const Node* tree)
    {
		if (!tree)
			return;
        cout << tree->key << "\n\t" << tree->hashValue << endl;
        Traverse2(tree->left);
        Traverse2(tree->right);
    }

    bool ReadBlock(int n)
    {
        if(n > blockNo)
        {
            cout << "Out of range!" << endl;
            return false;
        }

		// Go to the place of the node.
        string key = SHA256(to_string(n));
        Node* ptr = root;
		while (ptr->right)
		{
			if (key > ptr->right->key)
            {
                cout << "Right.\tKey: " << key << endl;
                cout << ptr->key << endl;
                cout << ptr->right->key << endl;
                cout << ptr->left->key << endl;
				ptr = ptr->right;
            }else
			{
                cout << "Left.\tKey: " << key << endl << ptr->right->key << endl;
				if (ptr->left)
					ptr = ptr->left;
				else
				{
					// Now, we are at level 0.
                    while (ptr)
                    {
                        if(ptr->key == key)
                        {
                            cout << "Found:\t" << ptr->key << endl << "\t" << ptr->value << endl << endl;
                            return true;
                        }
                        
                        ptr = ptr->right;
                    }
				}
			}
		}

		cout << "Not found!" << endl;
		return false;
    }

    // When a block is requested, find it, and return it with a proof of membership.
    string ProveBlock(int n)
    {
        string proof("");
        if(n > blockNo)
        {
            cout << "Not found!" << endl;
            return proof;
        }

        int tempN = n;
        Node* tree = root;
        for(int i = levels ; i >= 0 ; i--)
        {
            if(tempN < pow(2, i-1)) // Go left
            {
                if(tree->left)
                    tree = tree->left;
                else
                    cout << "Found: " << tree->hashValue << endl;
            }else
            {
                tempN -= pow(2, i-1);
                if(tree->right)
                    tree = tree->right;
                else
                    cout << "Found: " << tree->hashValue << endl;
            }
        }

        // Now prepare the proof:
        bool bFirst = true;
        Node *leftN = tree, *parentN = leftN->parent, *rightN = nullptr;
        while(parentN)
        {
            if(parentN->left == leftN)
            {
                rightN = parentN->right;
                if(bFirst)
                {
                    proof += "L:";
                    proof += leftN->value;
                    bFirst = false;
                }

                proof += "R:";
                proof += rightN->hashValue;
            }else
            {
                rightN = leftN;
                leftN = parentN->left;
                if(bFirst)
                {
                    proof += "R:";
                    proof += rightN->value;
                    bFirst = false;
                }

                proof += "L:";
                proof += leftN->hashValue;
            }

            leftN = parentN;
            parentN = parentN->parent;
        }

        return proof;
    }

    // Verify if the proof coming from the server is correct that means
    // whether of not the returned block is authentic.
    bool Verify(string proof)
    {
		string info(""), strHash(""), strTemp("");
        int index = 0, n = proof.length();
		// Read the first two characters
		info = proof.substr(0, 2);
		index = proof.find((info == "L:") ? "R:" : "L:", 2);
		strTemp = proof.substr(2, (index == string::npos) ? (n-2) : (index-2));
//        cout << "\nData: " << strTemp << endl << endl;
		strHash = SHA256(strTemp);
//        cout << "Hash: " << strHash << endl;

		while (index < n)
		{
			info = proof.substr(index, 2);
			index += 2;
			strTemp = proof.substr(index, HASHSIZE);
//            cout << "strTemp: " << strTemp << endl;
			if (info == "L:")
				strHash = SHA256(strTemp + strHash);
			else
				strHash = SHA256(strHash + strTemp);
			index += HASHSIZE;
		}

		if(strHash == root->hashValue)
            cout << "\n\n\t\tVerified!!!" << endl << endl;
        else
            cout << "\n\n\t\tNot Verified!!!" << endl << endl;
		return (strHash == root->hashValue);
    }
};

bool menu(SkipList& T)
{
    cout << endl << endl << "\tI)nsert a new block." << endl;
    cout << "\tR)equest a block." << endl;
    cout << "\tV)erify the proof." << endl;
    cout << "\tT)raverse the tree." << endl;
    cout << "\tQ)uit." << endl;
    cout << endl << "\tEnter your command: ";

    string strBlock("");
    int nBlock = -1;
    char ch = ' ';
    cin.get(ch);
    while(ch == 10)
        cin.get(ch);
    switch(ch)
    {
        case 'i':
        case 'I':
            cout << "\n\tEnter new block text: ";
            cin >> strBlock;
            T.Insert("01010101", strBlock);
            return true;
        case 'v':
        case 'V':
            T.Verify(strResult);
            return true;
        case 't':
        case 'T':
            T.PrintList();
            return true;
        case 'r':
        case 'R':
            cout << "\n\tEnter block no: ";
            cin >> nBlock;
            while(nBlock != -1)
            {
                strResult = T.ReadBlock(nBlock);
                cout << strResult << endl;
                cout << "\n\tEnter block no: ";
                cin >> nBlock;
            }
            return true;
        case 'q':
        case 'Q':
            return false;
    }

    return false;
}

int main()
{
    SkipList T(70);     // Give the block size (here it is 70 bytes).
    T.Build("inp.txt");   // Give you input file name.
    //T.Insert("01010101", "AAAAAAAAAAAAAAAAAAAA");
    while(menu(T))
        ;
    return 0;
}
