#ifndef __LOCALCACHE_H
#define __LOCALCACHE_H

#include <list>
#include <unordered_map>

template <class T> T NullDuplicator(T t) {return t;};

template <class T> void NullDeletor(T t) {};

template<class T, T (*DUPLICATOR)(T t), void ( *DELETOR)(T )> class LocalCache {
public:
    struct Item {
        Item(const std::string &k, time_t exp, T val): key(k), expires(exp), value(val) {};
        std::string key;
        time_t expires;
        T value;
    };
public:
    LocalCache(const std::string &_name, int _ttl, int _maxItems = -1): name(_name),  maxItems(_maxItems), ttl(_ttl) {}
    ~LocalCache() {
        while(!items.empty())
            deleteOlder_nl();
    }

    const T get(const std::string &key) {
        T val = nullptr;
        mtx.lock();
        purge_nl();
        if ((val = find_nl(key)))
            hits++;
        searches++;
        val = DUPLICATOR(val);
        mtx.unlock();
        return val;
    };

    bool store(const std::string &key, T value) {
        bool stored = false;
        time_t current;
        time(&current);
        mtx.lock();
        const bool foundKey  = (find_nl(key) != nullptr);
        purge_nl((foundKey ? 0 : 1));
        if (!foundKey) {
            value = DUPLICATOR(value);
            map.insert(std::make_pair(key, value));
            items.push_back(Item(key, current + ttl, value));
            stored = true;
            storedItems++;
            stores++;
        }
        mtx.unlock();
        return stored;
    }

private:
    const T find_nl(const std::string &key) {
        const auto it = map.find(key);
        if (it != map.cend()) {
            return it->second;
        }
        return nullptr;
   }
    void purge_nl(unsigned makeSpace = 0) {
        time_t current;
        time(&current);
        while(!items.empty() && items.front().expires < current)
            deleteOlder_nl();
        if (makeSpace && maxItems > 0) {
            while(storedItems > (maxItems - makeSpace))
                deleteOlder_nl();
        }
    }

    void deleteOlder_nl() {
        map.erase(items.front().key);
        DELETOR(items.front().value);
        items.pop_front();
        storedItems--;
        removed++;
    }
public:
    std::string name;
    int maxItems = -1;
    int ttl = 0;
    std::mutex mtx;
    unsigned storedItems = 0;
    std::list<Item> items;
    std::unordered_map<std::string, T> map;

    uint64_t searches = 0;
    uint64_t hits = 0;
    uint64_t stores = 0;
    uint64_t removed = 0;
};


#endif //__LOCALCACHE_H
