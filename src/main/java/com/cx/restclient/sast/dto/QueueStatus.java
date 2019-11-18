package com.cx.restclient.sast.dto;

/**
 * Created by Galn on 05/02/2018.
 */

public enum QueueStatus {
    New,
    PreScan,
    SourcePullingAndDeployment,
    Queued,
    Scanning,
    PostScan,
    Finished,
    Canceled,
    Failed;
}

