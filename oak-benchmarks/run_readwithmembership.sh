#!/bin/sh
#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
TITLE=ReadWithMembershipTest
BENCH="ReadWithMembershipTest"
RUNTIME=5
FIXS="Oak-Segment-Tar" # Jackrabbit"
THREADS="1,2,4,8,10,15,20,50"
PROFILE=true
NUM_ITEMS=1000
NUM_MEMBERSHIP="1 5 10 50 100"

LOG=$TITLE"_$(date +'%Y%m%d_%H%M%S').csv"
echo "Benchmarks: $BENCH" > $LOG
echo "Fixtures: $FIXS" >> $LOG
echo "Runtime: $RUNTIME" >> $LOG
echo "Num Items: $NUM_ITEMS" >> $LOG
echo "Concurrency: $THREADS" >> $LOG
echo "Number of Membership: $NUM_MEMBERSHIP" >> $LOG
echo "Profiling: $PROFILE" >> $LOG
echo "--------------------------------------" >> $LOG

for bm in $BENCH
    do
    for noOfGroups in $NUM_MEMBERSHIP
        do
        echo "Executing benchmark with number of group membership: $noOfGroups on $FIXS" | tee -a $LOG
        echo "-----------------------------------------------------------" | tee -a $LOG
            rm -rf target/Jackrabbit-* target/Oak-Tar-*
            cmd="java -Xmx2048m -Dprofile=$PROFILE -Druntime=$RUNTIME -Dwarmup=10 -jar target/oak-benchmarks-*-SNAPSHOT.jar benchmark --itemsToRead $NUM_ITEMS --numberOfGroups $noOfGroups --csvFile $LOG --concurrency $THREADS --report false $bm $FIXS"
            echo $cmd
            $cmd
    done
done
echo "-----------------------------------------"
echo "Benchmark completed. see $LOG for details:"
cat $LOG
