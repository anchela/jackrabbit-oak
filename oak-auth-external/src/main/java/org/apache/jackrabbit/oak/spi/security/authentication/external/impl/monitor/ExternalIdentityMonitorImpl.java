package org.apache.jackrabbit.oak.spi.security.authentication.external.impl.monitor;

import org.apache.jackrabbit.oak.spi.security.authentication.external.SyncException;
import org.apache.jackrabbit.oak.spi.security.authentication.external.SyncResult;
import org.apache.jackrabbit.oak.stats.MeterStats;
import org.apache.jackrabbit.oak.stats.StatisticsProvider;
import org.apache.jackrabbit.oak.stats.StatsOptions;
import org.apache.jackrabbit.oak.stats.TimerStats;
import org.jetbrains.annotations.NotNull;

import static java.util.concurrent.TimeUnit.NANOSECONDS;

public class ExternalIdentityMonitorImpl implements ExternalIdentityMonitor {

    private final TimerStats syncTimer;
    private final MeterStats syncRetries;
    private final TimerStats syncIdTimer;
    private final MeterStats syncFailed;

    public ExternalIdentityMonitorImpl(@NotNull StatisticsProvider statisticsProvider) {
        syncTimer = statisticsProvider.getTimer("security.authentication.external.sync_external_identity.timer", StatsOptions.METRICS_ONLY);
        syncRetries = statisticsProvider.getMeter("security.authentication.external.sync_external_identity.retries", StatsOptions.DEFAULT);
        syncIdTimer = statisticsProvider.getTimer("security.authentication.external.sync_id.timer", StatsOptions.METRICS_ONLY);
        syncFailed = statisticsProvider.getMeter("security.authentication.external.sync.failed", StatsOptions.DEFAULT);
    }

    @Override
    public void doneSyncExternalIdentity(long timeTakenNanos, @NotNull SyncResult result, int retryCount) {
        // TODO: decide which sync-result-status to exclude
        syncTimer.update(timeTakenNanos, NANOSECONDS);
        if (retryCount > 0){
            syncRetries.mark(retryCount);
        }
    }

    @Override
    public void doneSyncId(long timeTakenNanos, @NotNull SyncResult result) {
        // TODO: decide which sync-result-status to exclude
        syncIdTimer.update(timeTakenNanos, NANOSECONDS);
    }

    @Override
    public void syncFailed(@NotNull SyncException syncException) {
        syncFailed.mark();
    }
}
