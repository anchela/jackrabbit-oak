package org.apache.jackrabbit.oak.security.user.monitor;

import org.apache.jackrabbit.oak.stats.MeterStats;
import org.apache.jackrabbit.oak.stats.StatisticsProvider;
import org.apache.jackrabbit.oak.stats.StatsOptions;
import org.apache.jackrabbit.oak.stats.TimerStats;

import static java.util.concurrent.TimeUnit.NANOSECONDS;

public class UserMonitorImpl implements UserMonitor {

    private static final String ADD_MEMBERS_FAILED = "security.user.add_members.failed";
    private static final String ADD_MEMBERS_SUCCEEDED = "security.user.add_members.succeeded";
    private static final String ADD_MEMBERS_TIMER = "security.user.add_members.timer";

    private static final String REMOVE_MEMBERS_FAILED = "security.user.remove_members.failed";
    private static final String REMOVE_MEMBERS_SUCCEEDED = "security.user.remove_members.succeeded";
    private static final String  REMOVE_MEMBERS_TIMER = "security.user.remove_members.timer";

    private static final String  GET_MEMBERS_TIMER = "security.user.get_members.timer";
    private static final String  GET_DECLARED_MEMBERS_TIMER = "security.user.get_declared_members.timer";

    private static final String  MEMBEROF_TIMER = "security.user.memberof.timer";
    private static final String  DECLARED_MEMBEROF_TIMER = "security.user.declared_memberof.timer";

    private final MeterStats addMembersFailed;
    private final MeterStats addMembersSucceeded;
    private final TimerStats addMembersTimer;

    private final MeterStats removeMembersFailed;
    private final MeterStats removeMembersSucceeded;
    private final TimerStats removeMembersTimer;

    private final TimerStats getMembersTimer;
    private final TimerStats getDeclaredMembersTimer;

    private final TimerStats memberOfTimer;
    private final TimerStats declaredMemberOfTimer;

    public UserMonitorImpl(StatisticsProvider statisticsProvider) {
        addMembersFailed = statisticsProvider.getMeter(ADD_MEMBERS_FAILED, StatsOptions.DEFAULT);
        addMembersSucceeded = statisticsProvider.getMeter(ADD_MEMBERS_SUCCEEDED, StatsOptions.DEFAULT);
        addMembersTimer = statisticsProvider.getTimer(ADD_MEMBERS_TIMER, StatsOptions.METRICS_ONLY);

        removeMembersFailed = statisticsProvider.getMeter(REMOVE_MEMBERS_FAILED, StatsOptions.DEFAULT);
        removeMembersSucceeded = statisticsProvider.getMeter(REMOVE_MEMBERS_SUCCEEDED, StatsOptions.DEFAULT);
        removeMembersTimer = statisticsProvider.getTimer(REMOVE_MEMBERS_TIMER, StatsOptions.METRICS_ONLY);

        getMembersTimer = statisticsProvider.getTimer(GET_MEMBERS_TIMER, StatsOptions.METRICS_ONLY);
        getDeclaredMembersTimer = statisticsProvider.getTimer(GET_DECLARED_MEMBERS_TIMER, StatsOptions.METRICS_ONLY);

        memberOfTimer = statisticsProvider.getTimer(MEMBEROF_TIMER, StatsOptions.METRICS_ONLY);
        declaredMemberOfTimer = statisticsProvider.getTimer(DECLARED_MEMBEROF_TIMER, StatsOptions.METRICS_ONLY);
    }

    @Override
    public void doneGetMembers(long timeTakenNanos, boolean declaredOnly) {
        if (declaredOnly) {
            getMembersTimer.update(timeTakenNanos, NANOSECONDS);
        } else {
            getDeclaredMembersTimer.update(timeTakenNanos, NANOSECONDS);
        }
    }

    @Override
    public void doneMemberOf(long timeTakenNanos, boolean declaredOnly) {
        if (declaredOnly) {
            declaredMemberOfTimer.update(timeTakenNanos, NANOSECONDS);
        } else {
            memberOfTimer.update(timeTakenNanos, NANOSECONDS);
        }
    }

    @Override
    public void doneUpdateMembers(long timeTakenNanos, long totalProcessed, long failed, boolean isRemove) {
        long successCnt = totalProcessed - failed;
        if (isRemove) {
            removeMembersFailed.mark(failed);
            removeMembersSucceeded.mark(successCnt);
            removeMembersTimer.update(timeTakenNanos, NANOSECONDS);
        } else {
            addMembersFailed.mark(failed);
            addMembersSucceeded.mark(successCnt);
            addMembersTimer.update(timeTakenNanos, NANOSECONDS);
        }
    }
}
