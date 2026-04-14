// SPDX-License-Identifier: LGPL-2.1-or-later
package io.librescrs.dss;

import io.netty.channel.unix.DomainSocketAddress;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.embedded.netty.NettyServerCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class UnixSocketConfig {

    @Value("${server.socket-path:}")
    private String socketPath;

    @Bean
    public NettyServerCustomizer unixSocketCustomizer() {
        return httpServer -> {
            if (socketPath != null && !socketPath.isEmpty()) {
                return httpServer.bindAddress(() -> new DomainSocketAddress(socketPath));
            }
            return httpServer;
        };
    }
}
