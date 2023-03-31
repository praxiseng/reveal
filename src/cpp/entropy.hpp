#ifndef __ENTROPY_H__
#define __ENTROPY_H__

#include <stdlib.h>
#include <map>
#include <math.h>

/* Shannon entropy normalized to a 0-to-1 scale. */
template <typename T> 
static double 
shannon_entropy(T *data,size_t len)
{
    double h=0;
    std::map<T,double> counts;

    double incr = ((double)1)/len;
    for (size_t i=0; i<len; i++) {
        counts[data[i]]+=incr;
    }
    for(const auto& kv : counts) {
        double p_x = kv.second;
        h-=p_x*log(p_x);
    }
    return h / log(minval(256, len));
}


#endif