#include <algorithm>
#include <iostream>
#include <fstream> //// 파일 입출력
#include <bitset>
#include <string>
#include <tuple>
#include <ctime> //// 실행 시간 측정을 위해 추가함
#include <list>
#include <set>
using namespace std;
#define pss pair<string, string>
#define pii pair<int, int>

#define LI_BIT 9   // src-BF, dst-BF 비트 (individual)   // 50개의 요소를 오류율 0.01로 프로그래밍하기 위해서 약 479비트 크기의 필터 크기가 필요 -> 필터 크기를 512(=2^9)로 설정
#define LT_BIT 10  // tuple-BF 비트                      // 1k -> 18983, 2^15=32768   5k -> 94913, 2^17=131072   10k -> 189825, 2^18=262144
#define LH_BIT 9   // hash table 비트                    // 50k -> 949123, 2^20=1048576   100k -> 1898245, 2^21=2097152

#define IP_SIZE 32        // IP주소 크기 
#define RN 55            // rule 개수 << 좀 넉넉하게..?
#define LI 1 << LI_BIT   // src-BF, dst-BF 크기
#define LT 1 << LT_BIT   // tuple-BF 크기
#define LH 1 << LH_BIT   // hash table 크기
#define CRC_SIZE 32      // CRC 코드 길이
#define N RN             // maximum BMR value

#define PACKET_LOCATION "./input/input_test.txt"     // 패킷 데이터 파일 경로
#define RULE_LOCATION   "./rule/rule_test.txt"       // 룰 데이터 파일 경로
#define RESULT_LOCATION "./result/result_test.txt"   // 결과 파일 경로

// 입력 패킷 형식
struct packet {
    int idx;
    string srcIP;
    string dstIP;
    int srcPort;
    int dstPort;
    int protocolType;
};
// rule 형식
struct rule {
    int srcPrefixLength;
    string srcPrefix;
    int dstPrefixLength;
    string dstPrefix;
    int srcPortStart;
    int srcPortEnd;
    int dstPortStart;
    int dstPortEnd;
    int protocolType;
    int priority;
};

rule R[RN];
pii L[RN];

set<string> P1;  // rule의 source prefix 집합
set<string> P2;  // rule의 destination prefix 집합
set<int> L1;     // rule의 source prefix 길이 집합
set<int> L2;     // rule의 destination prefix 길이 집합
set<int> L1a1;   // packet의 sourve prefix 길이 집합
set<int> L2a2;   // packet의 destination prefix 길이 집합
set<pii> Lt;     // rule의 (src, dst) prefix 길이 집합
set<pii> L3;     // packet의 (src, dst) prefix 길이 집합
set<pii> Lc;     // Lt와 L3의 교집합

bool SRC_BF[LI];         // source-Bloom filter
bool DST_BF[LI];         // destination-Bloom filter
bool TUPLE_BF[LT];       // tuple-Bloom filter
list<int> Off_chip[LH];  // off-chip hash table

uint32_t CRC32_table[] = {    // CRC-32 연산을 수행할 때 필요
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
    0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
    0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
    0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
    0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
    0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924, 0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
    0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
    0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
    0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
    0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
    0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
    0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
    0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
    0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
    0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
    0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236, 0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
    0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
    0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
    0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
    0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
    0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
    0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

string CRC_32(const string& input) { //문제가 있으미...
    uint32_t crc = 0xFFFFFFFF;

    for (char byte : input) {
        crc = (crc >> 8) ^ CRC32_table[(crc ^ int(byte - '0')) & 0xFF];
    }
    //return crc ^ 0xFFFFFFFF;
    return bitset<32>(crc ^ 0xFFFFFFFF).to_string();
}

pii getidx(const string& crc, const int i) {  // crc 코드를 받아서 앞i자리, 뒷i자리로 인덱스 만들어서 pair로 반환해줌
    return pii(stoi(crc.substr(0, i), 0, 2), stoi(crc.substr(CRC_SIZE - i), 0, 2));
}

void makeFilter() {  //P1, P2, L1, L2, Lt, SRC_BF, DST_BF, TUPLE_BF 생성
    cout << "▶ makeFilter() start\n";
    string crc, ind1, ind2;
    int tmp, t[8];
    pii idx;

    fstream frule(RULE_LOCATION, ios::in); // rule 파일 열기
    if (!frule) cout << "rule file open failed.\n";

    int i = 0;
    while (!frule.eof()) {
        frule >> tmp >> R[i].srcPrefixLength >> t[0] >> t[1] >> t[2] >> t[3]
            >> tmp >> R[i].dstPrefixLength >> t[4] >> t[5] >> t[6] >> t[7]
            >> tmp >> R[i].srcPortStart >> R[i].srcPortEnd
            >> tmp >> R[i].dstPortStart >> R[i].dstPortEnd
            >> tmp >> tmp >> R[i].protocolType;  // 한 줄 (21개의 인수를 각각) 입력받음, 필요 없는 것은 tmp에

        if (frule.fail()) break;  // 파일의 맨 끝에 개행 문자만 있는 경우를 거름

        R[i].priority = i;  // 임시 priority 설정, 값이 작을수록 우선순위가 높음
        R[i].srcPrefix = (bitset<8>(t[0]).to_string() + bitset<8>(t[1]).to_string() + bitset<8>(t[2]).to_string() + bitset<8>(t[3]).to_string()).substr(0, R[i].srcPrefixLength);
        R[i].dstPrefix = (bitset<8>(t[4]).to_string() + bitset<8>(t[5]).to_string() + bitset<8>(t[6]).to_string() + bitset<8>(t[7]).to_string()).substr(0, R[i].dstPrefixLength);
        // decimal int인 IP 정보를 binary string으로 변환하고, prefix 길이만큼 자른 후 저장

        L[i] = pii(R[i].srcPrefixLength, R[i].dstPrefixLength);
        P1.insert(R[i].srcPrefix);
        P2.insert(R[i].dstPrefix);
        L1.insert(L[i].first);   // == R[i].srcPrefixLength
        L2.insert(L[i].second);  // == R[i].dstPrefixLength
        Lt.insert(L[i]);
        
        if (!R[i].srcPrefix.empty()) {
            crc = CRC_32(R[i].srcPrefix);
            idx = getidx(crc, LI_BIT);
            SRC_BF[idx.first] = 1; 
            SRC_BF[idx.second] = 1;
        }
        if (!R[i].dstPrefix.empty()) {
            crc = CRC_32(R[i].dstPrefix);
            idx = getidx(crc, LI_BIT);
            DST_BF[idx.first] = 1; 
            DST_BF[idx.second] = 1;
        }
        if (!(R[i].srcPrefix + R[i].dstPrefix).empty()) {
            crc = CRC_32(R[i].srcPrefix + R[i].dstPrefix);
            idx = getidx(crc, LT_BIT);
            TUPLE_BF[idx.first] = 1; 
            TUPLE_BF[idx.second] = 1;
            idx = getidx(crc, LH_BIT);
            Off_chip[idx.second].push_back(i + 1);
        }

        i++;
    }
    cout << i << " rules\n";
    cout << "◀ makeFilter() end\n\n";
}

void filterTest() {
    cout << "▶ Filter Test\n";

    cout << "SRC_BF" << endl;
    for (int i = 0; i < LI; i++) cout << SRC_BF[i] << ' ';
    cout << "\n\nDST_BF" << endl;
    for (int i = 0; i < LI; i++) cout << DST_BF[i] << ' ';
    cout << "\n\nTUPLE_BF" << endl;
    for (int i = 0; i < LT; i++) cout << TUPLE_BF[i] << ' ';
    cout << "\n\nOff_chip" << endl;
    for (int i = 0; i < LH; i++) {
        if (Off_chip[i].empty()) continue;
        cout << i << " : ";
        for (auto j : Off_chip[i]) cout << j << ' ';
        cout << endl;
    }

    cout << "◀ Filter Test end\n\n";
}

bool checkRule(const packet& in, const int i) {  // input packet이 실제로 rule에 부합하는지 검사
    //cout << "▶checkRule() start\n";
    for (int j = 0; R[i].srcPrefix[j]; j++) if (in.srcIP[j] != R[i].srcPrefix[j]) return false;  // source IP check
    for (int j = 0; R[i].dstPrefix[j]; j++) if (in.dstIP[j] != R[i].dstPrefix[j]) return false;  // destination IP check
    if (in.srcPort < R[i].srcPortStart || in.srcPort > R[i].srcPortEnd) return false;            // source port check
    if (in.dstPort < R[i].dstPortStart || in.dstPort > R[i].dstPortEnd) return false;            // destination port check
    if (in.protocolType != R[i].protocolType) return false;                                      // protocol type check

    //cout << "True\n";
    return true;
}

void Individual_Filter_Search(const packet& in) {
    //cout << "▶ Individual_Filter_Search() start\n";
    string crc; pii idx;

    //cout << "  ▶ L1 check\n";
    for (auto i = L1.begin(); i != L1.end(); i++) {
        //cout << "i : " << *i << "\n";
        crc = CRC_32(in.srcIP.substr(0, *i));
        idx = getidx(crc, LI_BIT);
        //cout << "idx: " << idx.first << ", " << idx.second << endl;
        if (((SRC_BF[idx.first] & SRC_BF[idx.second]) == 1) || *i == 0) { // positive
            L1a1.insert(*i);
            //cout << "L1a1.insert: " << *i << endl;
        }
    }
    //cout << "  ◀ L1 check end\n\n";

    //cout << "  ▶ L2 check\n";
    for (auto i = L2.begin(); i != L2.end(); i++) {
        //cout << "i : " << *i << "\n";
        crc = CRC_32(in.dstIP.substr(0, *i));
        idx = getidx(crc, LI_BIT);
        //cout << "idx: " << idx.first << ", " << idx.second << endl;
        if (((DST_BF[idx.first] & DST_BF[idx.second]) == 1) || *i == 0) { // positive
            L2a2.insert(*i);
            //cout << "L2a2.insert: " << *i << endl;
        }
    }
    //cout << "  ◀ L2 check end\n";

    //cout << "◀ Individual_Filter_Search() end\n\n";
}

int Tuple_Filter_Search(const packet& in) {
    //cout << "\n▶ Tuple_Filter_Search() start\n";

    int BMR = N - 1;  //lowest priority로 초기화

    for (auto i = Lc.begin(); i != Lc.end(); i++) {
        //cout << (*i).first << ", " << (*i).second << endl;

        pii l = *i;
        string tuple_value = in.srcIP.substr(0, l.first) + in.dstIP.substr(0, l.second);
        string crc = CRC_32(tuple_value);
        pii idx = getidx(crc, LT_BIT);  //tuple-BF용 인덱스 2개 구함
        //cout << "idx: " << idx.first << ", " << idx.second << endl;

        if ((TUPLE_BF[idx.first] & TUPLE_BF[idx.second]) == 1) { // positive
            //cout << "positive\n";
            pii idx_hash = getidx(crc, LH_BIT);
            //cout << "idx_hash: " << idx_hash.second << endl;
            for (auto j : Off_chip[idx_hash.second]) {  //////////////////// Off-chip memory access가 발생하는 부분
                //cout << j << endl;
                if (checkRule(in, j - 1)) BMR = min(BMR, R[j - 1].priority);
            }
        }
    }

    //cout << "◀ Tuple_Filter_Search() end\n";
    return BMR;
}

int Search(const packet& in) {
    //cout << "▶ Search() start\n";

    L1a1.clear(); L2a2.clear(); L3.clear(); Lc.clear();  //L 집합들 초기화

    Individual_Filter_Search(in);  // L1a1, L2a2 생성

    //cout << "  ▶ make L3\n";
    for (auto i = L1a1.begin(); i != L1a1.end(); i++) {
        //cout << "*i: " << *i;
        for (auto j = L2a2.begin(); j != L2a2.end(); j++) {
            //cout << "   *j: " << *j;
            L3.insert(pii(*i, *j));
        }
        //cout << endl;
    }  // L3 = (L1a1, L2a2)
    //for (auto i = L3.begin(); i != L3.end(); i++) cout << (*i).first << ", " << (*i).second << endl;

    //cout << "  ▶ make Lc\n";
    // Lc = Lt ∩ L3 = Lt ∩ (L1a1, L2a2)
    set_intersection(Lt.begin(), Lt.end(), L3.begin(), L3.end(), inserter(Lc, Lc.begin()));
    //for (auto i = Lc.begin(); i != Lc.end(); i++) cout << (*i).first << ", " << (*i).second << endl;

    //int BMR = Tuple_Filter_Search(in);
    //cout << "◀ Search() end\n";
    return Tuple_Filter_Search(in);
}

void makeTestFile() {
    //요소가 각각 50개씩인 패킷 테스트 파일과 룰 테스트 파일 생성
    fstream fpacket("./input/input_acl1k.txt", ios::in);
    fstream frule("./rule/rule_acl1k.txt", ios::in);
    fstream fpktest("./input/input_test.txt", ios::out);
    fstream frltest("./rule/rule_test.txt", ios::out);
    if (!fpacket) cout << "packet file open failed.\n";
    if (!frule) cout << "rule file open failed.\n";
    if (!fpktest) cout << "pktest file open failed.\n";
    if (!frltest) cout << "rltest file open failed.\n";
    string aa;
    for (int i = 0; i < 50; i++) {
        getline(frule, aa);
        frltest << aa << endl;
        getline(fpacket, aa);
        fpktest << aa << endl;
    }
}

int main()
{

    cout << "packet file : " << PACKET_LOCATION 
        << "\nrule file   : " << RULE_LOCATION 
        << "\nresult file : " << RESULT_LOCATION << "\n\n";

    clock_t start, middle, finish;
    start = clock();

    makeFilter();
    middle = clock();
    cout << "\n실행시간: " << middle - start << "ms\n\n";

    filterTest();

    fstream fpacket(PACKET_LOCATION, ios::in);  // 패킷 파일 열기
    if (!fpacket) cout << "packet file open failed.\n";
    fstream fres(RESULT_LOCATION, ios::out);
    if (!fres) cout << "result file open failed.\n";

    int i = 0;
    packet a;
    while (!fpacket.eof()) {
        fpacket >> a.idx >> a.srcIP >> a.dstIP >> a.srcPort >> a.dstPort >> a.protocolType;  // 한 줄(6개의 인수) 읽어들임
        //fpacket >> a.srcIP >> a.dstIP >> a.srcPort >> a.dstPort >> a.protocolType;  // 50k, 100k 데이터는 패킷 번호가 없으므로 idx 없이 읽어들임
        if (fpacket.fail()) break;  // 파일의 맨 끝에 개행 문자만 있는 경우를 거름
        
        int BMR = Search(a);

        fres << i++ << " : ";
        if (BMR == N-1) fres << "Not found\n";
        else fres << BMR << "\n";
    }
    cout << i << " packets\n";

    finish = clock();
    cout << "\n실행시간: " << finish - middle << "ms\n";
}
