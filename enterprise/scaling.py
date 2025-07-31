"""
Enterprise Scaling Module
Provides enterprise-grade scalability and performance features for all SOC agents
"""

import logging
import asyncio
import aiohttp
import json
import time
import psutil
import threading
from typing import Dict, Any, List, Optional, Callable, Union
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import queue
import multiprocessing
import redis
import consul
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

class ScalingMode(Enum):
    """Scaling mode enumeration"""
    VERTICAL = "vertical"
    HORIZONTAL = "horizontal"
    AUTO = "auto"

class LoadBalancingStrategy(Enum):
    """Load balancing strategy enumeration"""
    ROUND_ROBIN = "round_robin"
    LEAST_CONNECTIONS = "least_connections"
    WEIGHTED_ROUND_ROBIN = "weighted_round_robin"
    RESOURCE_BASED = "resource_based"

class HealthStatus(Enum):
    """Node health status enumeration"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    MAINTENANCE = "maintenance"

@dataclass
class NodeMetrics:
    """Node performance metrics"""
    node_id: str
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    network_io: float
    active_connections: int
    request_rate: float
    response_time: float
    error_rate: float
    timestamp: datetime

@dataclass
class ScalingDecision:
    """Scaling decision data"""
    action: str  # scale_up, scale_down, maintain
    target_nodes: int
    reason: str
    confidence: float
    metrics: Dict[str, Any]
    timestamp: datetime

class EnterpriseScalingManager:
    """
    Enterprise Scaling Manager
    Handles clustering, load balancing, and auto-scaling for SOC agents
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.cluster_manager = None
        self.load_balancer = None
        self.auto_scaler = None
        self.performance_monitor = None
        self.connection_pool = None
        self._initialize_scaling_components()
    
    def _initialize_scaling_components(self):
        """Initialize all scaling components"""
        try:
            # Initialize cluster management
            self.cluster_manager = ClusterManager(self.config)
            
            # Initialize load balancer
            self.load_balancer = EnterpriseLoadBalancer(self.config)
            
            # Initialize auto-scaler
            self.auto_scaler = AutoScaler(self.config)
            
            # Initialize performance monitor
            self.performance_monitor = PerformanceMonitor(self.config)
            
            # Initialize connection pool
            self.connection_pool = ConnectionPoolManager(self.config)
            
            logger.info("Enterprise scaling components initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize scaling components: {str(e)}")
            raise
    
    async def start_cluster(self, initial_nodes: int = 3) -> Dict[str, Any]:
        """
        Start enterprise cluster with specified number of nodes
        """
        try:
            cluster_info = await self.cluster_manager.initialize_cluster(initial_nodes)
            
            # Start load balancer
            await self.load_balancer.start(cluster_info["nodes"])
            
            # Start auto-scaler
            await self.auto_scaler.start(cluster_info)
            
            # Start performance monitoring
            await self.performance_monitor.start_monitoring(cluster_info["nodes"])
            
            logger.info(f"Enterprise cluster started with {initial_nodes} nodes")
            
            return {
                "cluster_id": cluster_info["cluster_id"],
                "nodes": cluster_info["nodes"],
                "load_balancer_endpoint": cluster_info.get("load_balancer_endpoint"),
                "status": "running",
                "scaling_enabled": True
            }
            
        except Exception as e:
            logger.error(f"Failed to start cluster: {str(e)}")
            raise
    
    async def scale_cluster(self, target_nodes: int, 
                          scaling_mode: ScalingMode = ScalingMode.AUTO) -> Dict[str, Any]:
        """
        Scale cluster to target number of nodes
        """
        try:
            current_nodes = await self.cluster_manager.get_active_nodes()
            current_count = len(current_nodes)
            
            if target_nodes == current_count:
                return {"status": "no_change", "current_nodes": current_count}
            
            scaling_result = {}
            
            if target_nodes > current_count:
                # Scale up
                new_nodes = await self.cluster_manager.add_nodes(
                    target_nodes - current_count
                )
                await self.load_balancer.add_nodes(new_nodes)
                scaling_result = {
                    "action": "scale_up",
                    "nodes_added": len(new_nodes),
                    "new_nodes": new_nodes
                }
                
            else:
                # Scale down
                nodes_to_remove = current_count - target_nodes
                removed_nodes = await self.cluster_manager.remove_nodes(nodes_to_remove)
                await self.load_balancer.remove_nodes(removed_nodes)
                scaling_result = {
                    "action": "scale_down",
                    "nodes_removed": len(removed_nodes),
                    "removed_nodes": removed_nodes
                }
            
            # Update monitoring
            updated_nodes = await self.cluster_manager.get_active_nodes()
            await self.performance_monitor.update_monitored_nodes(updated_nodes)
            
            logger.info(f"Cluster scaled to {target_nodes} nodes")
            
            return {
                "status": "success",
                "scaling_mode": scaling_mode.value,
                "target_nodes": target_nodes,
                "current_nodes": len(updated_nodes),
                **scaling_result
            }
            
        except Exception as e:
            logger.error(f"Failed to scale cluster: {str(e)}")
            raise
    
    async def process_distributed_workload(self, workload: List[Dict[str, Any]], 
                                         processing_function: Callable) -> List[Any]:
        """
        Process workload across cluster nodes with load balancing
        """
        try:
            # Get available nodes
            available_nodes = await self.cluster_manager.get_healthy_nodes()
            
            if not available_nodes:
                raise Exception("No healthy nodes available for processing")
            
            # Distribute workload
            distributed_tasks = await self.load_balancer.distribute_workload(
                workload, available_nodes
            )
            
            # Process tasks in parallel across nodes
            results = []
            tasks = []
            
            for node_id, node_workload in distributed_tasks.items():
                task = asyncio.create_task(
                    self._process_node_workload(node_id, node_workload, processing_function)
                )
                tasks.append(task)
            
            # Wait for all tasks to complete
            node_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Collect results
            for node_result in node_results:
                if isinstance(node_result, Exception):
                    logger.error(f"Node processing failed: {str(node_result)}")
                    # Handle node failure - redistribute work if needed
                else:
                    results.extend(node_result)
            
            return results
            
        except Exception as e:
            logger.error(f"Distributed processing failed: {str(e)}")
            raise
    
    async def get_cluster_metrics(self) -> Dict[str, Any]:
        """
        Get comprehensive cluster performance metrics
        """
        try:
            # Get cluster status
            cluster_status = await self.cluster_manager.get_cluster_status()
            
            # Get node metrics
            node_metrics = await self.performance_monitor.get_all_node_metrics()
            
            # Get load balancer metrics
            lb_metrics = await self.load_balancer.get_metrics()
            
            # Get auto-scaler status
            scaler_status = await self.auto_scaler.get_status()
            
            # Calculate aggregate metrics
            total_cpu = sum(m.cpu_usage for m in node_metrics) / len(node_metrics) if node_metrics else 0
            total_memory = sum(m.memory_usage for m in node_metrics) / len(node_metrics) if node_metrics else 0
            total_requests = sum(m.request_rate for m in node_metrics) if node_metrics else 0
            avg_response_time = sum(m.response_time for m in node_metrics) / len(node_metrics) if node_metrics else 0
            
            return {
                "cluster": cluster_status,
                "nodes": {
                    "total_nodes": len(node_metrics),
                    "healthy_nodes": len([m for m in node_metrics if m.cpu_usage < 80]),
                    "avg_cpu_usage": total_cpu,
                    "avg_memory_usage": total_memory,
                    "total_request_rate": total_requests,
                    "avg_response_time": avg_response_time
                },
                "load_balancer": lb_metrics,
                "auto_scaler": scaler_status,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get cluster metrics: {str(e)}")
            raise
    
    async def _process_node_workload(self, node_id: str, workload: List[Dict[str, Any]], 
                                   processing_function: Callable) -> List[Any]:
        """Process workload on specific node"""
        try:
            # Get node connection
            node_session = await self.connection_pool.get_node_session(node_id)
            
            # Process workload items
            results = []
            for item in workload:
                result = await processing_function(item, node_session)
                results.append(result)
            
            return results
            
        except Exception as e:
            logger.error(f"Node {node_id} processing failed: {str(e)}")
            raise


class ClusterManager:
    """Enterprise cluster management"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.cluster_id = None
        self.nodes = {}
        self.service_discovery = None
        self._initialize_service_discovery()
    
    def _initialize_service_discovery(self):
        """Initialize service discovery (Consul)"""
        try:
            consul_config = self.config.get("consul", {})
            self.service_discovery = consul.Consul(
                host=consul_config.get("host", "localhost"),
                port=consul_config.get("port", 8500)
            )
        except Exception as e:
            logger.warning(f"Service discovery not available: {str(e)}")
            self.service_discovery = MockServiceDiscovery()
    
    async def initialize_cluster(self, initial_nodes: int) -> Dict[str, Any]:
        """Initialize cluster with initial nodes"""
        try:
            self.cluster_id = f"soc-cluster-{int(time.time())}"
            
            # Create initial nodes
            nodes = []
            for i in range(initial_nodes):
                node = await self._create_node(f"node-{i}")
                nodes.append(node)
                self.nodes[node["node_id"]] = node
            
            # Register cluster in service discovery
            await self._register_cluster(nodes)
            
            logger.info(f"Cluster {self.cluster_id} initialized with {len(nodes)} nodes")
            
            return {
                "cluster_id": self.cluster_id,
                "nodes": nodes,
                "load_balancer_endpoint": f"http://lb.{self.cluster_id}.local:8080"
            }
            
        except Exception as e:
            logger.error(f"Failed to initialize cluster: {str(e)}")
            raise
    
    async def add_nodes(self, count: int) -> List[Dict[str, Any]]:
        """Add nodes to cluster"""
        new_nodes = []
        current_count = len(self.nodes)
        
        for i in range(count):
            node = await self._create_node(f"node-{current_count + i}")
            new_nodes.append(node)
            self.nodes[node["node_id"]] = node
        
        # Register new nodes
        for node in new_nodes:
            await self._register_node(node)
        
        return new_nodes
    
    async def remove_nodes(self, count: int) -> List[str]:
        """Remove nodes from cluster"""
        # Select nodes to remove (prefer least loaded)
        node_list = list(self.nodes.values())
        nodes_to_remove = sorted(node_list, key=lambda x: x.get("load", 0))[:count]
        
        removed_node_ids = []
        for node in nodes_to_remove:
            node_id = node["node_id"]
            await self._graceful_shutdown_node(node_id)
            await self._deregister_node(node_id)
            del self.nodes[node_id]
            removed_node_ids.append(node_id)
        
        return removed_node_ids
    
    async def get_active_nodes(self) -> List[Dict[str, Any]]:
        """Get list of active nodes"""
        return list(self.nodes.values())
    
    async def get_healthy_nodes(self) -> List[Dict[str, Any]]:
        """Get list of healthy nodes"""
        healthy_nodes = []
        for node in self.nodes.values():
            if await self._check_node_health(node["node_id"]):
                healthy_nodes.append(node)
        return healthy_nodes
    
    async def get_cluster_status(self) -> Dict[str, Any]:
        """Get cluster status"""
        total_nodes = len(self.nodes)
        healthy_nodes = len(await self.get_healthy_nodes())
        
        return {
            "cluster_id": self.cluster_id,
            "total_nodes": total_nodes,
            "healthy_nodes": healthy_nodes,
            "unhealthy_nodes": total_nodes - healthy_nodes,
            "status": "healthy" if healthy_nodes > total_nodes * 0.7 else "degraded"
        }
    
    async def _create_node(self, node_name: str) -> Dict[str, Any]:
        """Create a new cluster node"""
        node = {
            "node_id": f"{self.cluster_id}-{node_name}",
            "host": f"{node_name}.{self.cluster_id}.local",
            "port": 8080,
            "status": HealthStatus.HEALTHY.value,
            "created_at": datetime.now().isoformat(),
            "load": 0.0,
            "capacity": 100
        }
        return node
    
    async def _register_cluster(self, nodes: List[Dict[str, Any]]):
        """Register cluster in service discovery"""
        if self.service_discovery:
            try:
                self.service_discovery.kv.put(
                    f"clusters/{self.cluster_id}/config",
                    json.dumps({
                        "cluster_id": self.cluster_id,
                        "created_at": datetime.now().isoformat(),
                        "node_count": len(nodes)
                    })
                )
            except Exception as e:
                logger.warning(f"Failed to register cluster: {str(e)}")
    
    async def _register_node(self, node: Dict[str, Any]):
        """Register node in service discovery"""
        if self.service_discovery:
            try:
                self.service_discovery.agent.service.register(
                    name="soc-agent",
                    service_id=node["node_id"],
                    address=node["host"],
                    port=node["port"],
                    check=consul.Check.http(f"http://{node['host']}:{node['port']}/health", interval="10s")
                )
            except Exception as e:
                logger.warning(f"Failed to register node: {str(e)}")
    
    async def _deregister_node(self, node_id: str):
        """Deregister node from service discovery"""
        if self.service_discovery:
            try:
                self.service_discovery.agent.service.deregister(node_id)
            except Exception as e:
                logger.warning(f"Failed to deregister node: {str(e)}")
    
    async def _check_node_health(self, node_id: str) -> bool:
        """Check if node is healthy"""
        # Implementation would check actual node health
        node = self.nodes.get(node_id)
        return node and node.get("status") == HealthStatus.HEALTHY.value
    
    async def _graceful_shutdown_node(self, node_id: str):
        """Gracefully shutdown node"""
        # Implementation would drain connections and shutdown gracefully
        if node_id in self.nodes:
            self.nodes[node_id]["status"] = HealthStatus.MAINTENANCE.value


class EnterpriseLoadBalancer:
    """Enterprise load balancer with multiple strategies"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.strategy = LoadBalancingStrategy(
            config.get("load_balancing_strategy", LoadBalancingStrategy.RESOURCE_BASED.value)
        )
        self.nodes = []
        self.current_index = 0
        self.node_weights = {}
        self.connection_counts = {}
    
    async def start(self, nodes: List[Dict[str, Any]]):
        """Start load balancer with initial nodes"""
        self.nodes = nodes
        for node in nodes:
            self.connection_counts[node["node_id"]] = 0
            self.node_weights[node["node_id"]] = 1.0
    
    async def add_nodes(self, new_nodes: List[Dict[str, Any]]):
        """Add new nodes to load balancer"""
        self.nodes.extend(new_nodes)
        for node in new_nodes:
            self.connection_counts[node["node_id"]] = 0
            self.node_weights[node["node_id"]] = 1.0
    
    async def remove_nodes(self, removed_node_ids: List[str]):
        """Remove nodes from load balancer"""
        self.nodes = [n for n in self.nodes if n["node_id"] not in removed_node_ids]
        for node_id in removed_node_ids:
            self.connection_counts.pop(node_id, None)
            self.node_weights.pop(node_id, None)
    
    async def select_node(self) -> Optional[Dict[str, Any]]:
        """Select node based on load balancing strategy"""
        if not self.nodes:
            return None
        
        if self.strategy == LoadBalancingStrategy.ROUND_ROBIN:
            return await self._round_robin_selection()
        elif self.strategy == LoadBalancingStrategy.LEAST_CONNECTIONS:
            return await self._least_connections_selection()
        elif self.strategy == LoadBalancingStrategy.WEIGHTED_ROUND_ROBIN:
            return await self._weighted_round_robin_selection()
        elif self.strategy == LoadBalancingStrategy.RESOURCE_BASED:
            return await self._resource_based_selection()
        else:
            return self.nodes[0]
    
    async def distribute_workload(self, workload: List[Dict[str, Any]], 
                                nodes: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Distribute workload across nodes"""
        if not nodes or not workload:
            return {}
        
        distribution = {node["node_id"]: [] for node in nodes}
        
        # Calculate distribution based on node capacity
        total_capacity = sum(node.get("capacity", 100) for node in nodes)
        
        for i, item in enumerate(workload):
            # Select node based on capacity-weighted distribution
            selected_node = nodes[i % len(nodes)]
            distribution[selected_node["node_id"]].append(item)
        
        return distribution
    
    async def get_metrics(self) -> Dict[str, Any]:
        """Get load balancer metrics"""
        total_connections = sum(self.connection_counts.values())
        avg_connections = total_connections / len(self.nodes) if self.nodes else 0
        
        return {
            "strategy": self.strategy.value,
            "total_nodes": len(self.nodes),
            "total_connections": total_connections,
            "avg_connections_per_node": avg_connections,
            "node_weights": self.node_weights.copy(),
            "connection_distribution": self.connection_counts.copy()
        }
    
    async def _round_robin_selection(self) -> Dict[str, Any]:
        """Round robin node selection"""
        if not self.nodes:
            return None
        
        node = self.nodes[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.nodes)
        return node
    
    async def _least_connections_selection(self) -> Dict[str, Any]:
        """Least connections node selection"""
        if not self.nodes:
            return None
        
        return min(self.nodes, key=lambda n: self.connection_counts.get(n["node_id"], 0))
    
    async def _weighted_round_robin_selection(self) -> Dict[str, Any]:
        """Weighted round robin node selection"""
        # Implementation would use weights for selection
        return await self._round_robin_selection()
    
    async def _resource_based_selection(self) -> Dict[str, Any]:
        """Resource-based node selection"""
        if not self.nodes:
            return None
        
        # Select node with lowest load
        return min(self.nodes, key=lambda n: n.get("load", 0))


class AutoScaler:
    """Enterprise auto-scaling manager"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.cluster_info = None
        self.scaling_enabled = True
        self.min_nodes = config.get("min_nodes", 2)
        self.max_nodes = config.get("max_nodes", 20)
        self.target_cpu_utilization = config.get("target_cpu_utilization", 70)
        self.scaling_cooldown = config.get("scaling_cooldown_seconds", 300)
        self.last_scaling_action = None
    
    async def start(self, cluster_info: Dict[str, Any]):
        """Start auto-scaler"""
        self.cluster_info = cluster_info
        # Start scaling loop
        asyncio.create_task(self._scaling_loop())
    
    async def get_status(self) -> Dict[str, Any]:
        """Get auto-scaler status"""
        return {
            "enabled": self.scaling_enabled,
            "min_nodes": self.min_nodes,
            "max_nodes": self.max_nodes,
            "target_cpu_utilization": self.target_cpu_utilization,
            "last_scaling_action": self.last_scaling_action,
            "cooldown_remaining": self._get_cooldown_remaining()
        }
    
    async def make_scaling_decision(self, metrics: List[NodeMetrics]) -> Optional[ScalingDecision]:
        """Make scaling decision based on metrics"""
        if not metrics or not self.scaling_enabled:
            return None
        
        # Check cooldown period
        if self._is_in_cooldown():
            return None
        
        # Calculate average CPU utilization
        avg_cpu = sum(m.cpu_usage for m in metrics) / len(metrics)
        current_nodes = len(metrics)
        
        # Scaling logic
        if avg_cpu > self.target_cpu_utilization + 20:  # Scale up threshold
            if current_nodes < self.max_nodes:
                target_nodes = min(current_nodes + 1, self.max_nodes)
                return ScalingDecision(
                    action="scale_up",
                    target_nodes=target_nodes,
                    reason=f"High CPU utilization: {avg_cpu:.1f}%",
                    confidence=0.8,
                    metrics={"avg_cpu": avg_cpu, "current_nodes": current_nodes},
                    timestamp=datetime.now()
                )
        
        elif avg_cpu < self.target_cpu_utilization - 20:  # Scale down threshold
            if current_nodes > self.min_nodes:
                target_nodes = max(current_nodes - 1, self.min_nodes)
                return ScalingDecision(
                    action="scale_down",
                    target_nodes=target_nodes,
                    reason=f"Low CPU utilization: {avg_cpu:.1f}%",
                    confidence=0.7,
                    metrics={"avg_cpu": avg_cpu, "current_nodes": current_nodes},
                    timestamp=datetime.now()
                )
        
        return None
    
    async def _scaling_loop(self):
        """Auto-scaling monitoring loop"""
        while self.scaling_enabled:
            try:
                await asyncio.sleep(60)  # Check every minute
                # Implementation would check metrics and make scaling decisions
            except Exception as e:
                logger.error(f"Auto-scaling loop error: {str(e)}")
                await asyncio.sleep(60)
    
    def _is_in_cooldown(self) -> bool:
        """Check if in scaling cooldown period"""
        if not self.last_scaling_action:
            return False
        
        elapsed = (datetime.now() - self.last_scaling_action).total_seconds()
        return elapsed < self.scaling_cooldown
    
    def _get_cooldown_remaining(self) -> int:
        """Get remaining cooldown time in seconds"""
        if not self.last_scaling_action:
            return 0
        
        elapsed = (datetime.now() - self.last_scaling_action).total_seconds()
        remaining = max(0, self.scaling_cooldown - elapsed)
        return int(remaining)


class PerformanceMonitor:
    """Enterprise performance monitoring"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.monitored_nodes = []
        self.metrics_history = []
        self.monitoring_enabled = True
    
    async def start_monitoring(self, nodes: List[Dict[str, Any]]):
        """Start monitoring nodes"""
        self.monitored_nodes = nodes
        # Start monitoring loop
        asyncio.create_task(self._monitoring_loop())
    
    async def update_monitored_nodes(self, nodes: List[Dict[str, Any]]):
        """Update list of monitored nodes"""
        self.monitored_nodes = nodes
    
    async def get_all_node_metrics(self) -> List[NodeMetrics]:
        """Get metrics for all monitored nodes"""
        metrics = []
        for node in self.monitored_nodes:
            node_metrics = await self._collect_node_metrics(node)
            metrics.append(node_metrics)
        return metrics
    
    async def _monitoring_loop(self):
        """Performance monitoring loop"""
        while self.monitoring_enabled:
            try:
                metrics = await self.get_all_node_metrics()
                self.metrics_history.extend(metrics)
                
                # Keep only last hour of metrics
                cutoff_time = datetime.now() - timedelta(hours=1)
                self.metrics_history = [
                    m for m in self.metrics_history 
                    if m.timestamp > cutoff_time
                ]
                
                await asyncio.sleep(30)  # Collect metrics every 30 seconds
                
            except Exception as e:
                logger.error(f"Performance monitoring error: {str(e)}")
                await asyncio.sleep(30)
    
    async def _collect_node_metrics(self, node: Dict[str, Any]) -> NodeMetrics:
        """Collect metrics for a specific node"""
        # In production, this would collect actual metrics from the node
        # For now, simulate metrics
        return NodeMetrics(
            node_id=node["node_id"],
            cpu_usage=psutil.cpu_percent(),
            memory_usage=psutil.virtual_memory().percent,
            disk_usage=psutil.disk_usage('/').percent,
            network_io=100.0,  # Simulated
            active_connections=node.get("connections", 0),
            request_rate=node.get("request_rate", 0),
            response_time=node.get("response_time", 100),
            error_rate=node.get("error_rate", 0),
            timestamp=datetime.now()
        )


class ConnectionPoolManager:
    """Enterprise connection pool management"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.pools = {}
        self.max_connections = config.get("max_connections_per_pool", 100)
        self.min_connections = config.get("min_connections_per_pool", 10)
    
    async def get_node_session(self, node_id: str) -> aiohttp.ClientSession:
        """Get HTTP session for specific node"""
        if node_id not in self.pools:
            self.pools[node_id] = await self._create_connection_pool(node_id)
        
        return self.pools[node_id]
    
    async def _create_connection_pool(self, node_id: str) -> aiohttp.ClientSession:
        """Create connection pool for node"""
        connector = aiohttp.TCPConnector(
            limit=self.max_connections,
            limit_per_host=self.max_connections,
            ttl_dns_cache=300,
            use_dns_cache=True,
            keepalive_timeout=60,
            enable_cleanup_closed=True
        )
        
        return aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=30)
        )


class MockServiceDiscovery:
    """Mock service discovery for development"""
    
    def __init__(self):
        self.services = {}
        self.kv_store = {}
    
    class MockAgent:
        class MockService:
            def register(self, **kwargs):
                pass
            
            def deregister(self, service_id):
                pass
        
        def __init__(self):
            self.service = self.MockService()
    
    class MockKV:
        def __init__(self, store):
            self.store = store
        
        def put(self, key, value):
            self.store[key] = value
        
        def get(self, key):
            return self.store.get(key)
    
    def __init__(self):
        self.services = {}
        self.kv_store = {}
        self.agent = self.MockAgent()
        self.kv = self.MockKV(self.kv_store)
