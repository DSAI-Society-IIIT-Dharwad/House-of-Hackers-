#!/usr/bin/env python3
import asyncio
import uuid
import sys
import os
import time
import json
import hashlib
from datetime import datetime
from typing import Optional, Dict, Any, List, Set
from dotenv import load_dotenv
load_dotenv()
load_dotenv(".env.local", override=True)
# Rich imports for beautiful CLI
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text
from rich.columns import Columns
from rich.align import Align
from rich import box
from rich.status import Status
from rich.tree import Tree
from rich.console import Group
from rich.markdown import Markdown
from rich.padding import Padding
from rich.prompt import Prompt
from rich import markup

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))


# Decepticon imports
from langchain_core.messages import HumanMessage, AIMessage, ToolMessage
from langchain_core.runnables import RunnableConfig
from src.utils.llm.models import (
    list_available_models, 
    check_ollama_connection,
    validate_api_key
)
from src.graphs.swarm import create_dynamic_swarm  #  swarm  import
from src.utils.llm.config_manager import (
    update_llm_config, 
    get_current_llm_config,
    get_current_llm
)
from src.utils.message import (
    extract_message_content,
    extract_tool_calls,
    parse_tool_call,
    get_agent_name,
    parse_tool_name
)
# Persistence 
from src.utils.memory import (
    get_persistence_status,
    get_debug_info,
    create_thread_config,
    create_memory_namespace
)
# 
from src.utils.logging.logger import get_logger
# 
from src.utils.agents import AgentManager




console = Console()

class DecepticonCLI:
    def __init__(self):
        self.console = Console()
        self.thread_id = None
        self.config = None
        self.conversation_history = []
        self.strat_time = None
        self.end_time = None
        
        # 
        self.current_model = None  # 
        self.current_llm = None    # 
        self.swarm = None          #  swarm
        
        # 
        self.agents_config = {}
        self.tools_config = {}
        
        # Persistence 
        self.user_id = self._generate_user_id()
        self.memory_namespace = create_memory_namespace(self.user_id, "memories")
        
        # 
        self.logger = get_logger()
        self.logging_session_id = None
        
        # 
        self._load_dynamic_config()
    
    def _generate_user_id(self):
        """ ID  (CLI )"""
        # CLI ID 
        session_info = f"{os.getpid()}_{datetime.now().strftime('%Y%m%d')}_{os.environ.get('USER', 'unknown')}"
        user_hash = hashlib.md5(session_info.encode()).hexdigest()[:8]
        return f"cli_user_{user_hash}"
    
    def _load_dynamic_config(self):
        """"""
        try:
            # MCP 
            self._load_agents_from_mcp_config()
        except Exception as e:
            self.console.print(f"[yellow]Warning: Could not load dynamic config: {str(e)}[/yellow]")
            self.agents_config = {}
    
    def _load_agents_from_mcp_config(self):
        """MCP """
        try:
            with open("mcp_config.json", "r", encoding="utf-8") as f:
                mcp_config = json.load(f)
            
            # MCP 설정에서 에이전트 목록 추출
            for agent_name, servers in mcp_config.items():
                self.agents_config[agent_name] = {
                    "servers": servers,
                    "tools": []
                }
                
        except FileNotFoundError:
            self.agents_config = {}
    

    def display_banner(self):
        """Decepticon """
        banner_text = """
██████╗ ███████╗ ██████╗███████╗██████╗ ████████╗██╗ ██████╗ ██████╗ ███╗   ██║
██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗╚══██╔══╝██║██╔════╝██╔═══██╗████╗  ██║
██║  ██║█████╗  ██║     █████╗  ██████╔╝   ██║   ██║██║     ██║   ██║██╔██╗ ██║
██║  ██║██╔══╝  ██║     ██╔══╝  ██╔═══╝    ██║   ██║██║     ██║   ██║██║╚██╗██║
██████╔╝███████╗╚██████╗███████╗██║        ██║   ██║╚██████╗╚██████╔╝██║ ╚████║
╚═════╝ ╚══════╝ ╚═════╝╚══════╝╚═╝        ╚═╝   ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝   
        """
        
        banner_panel = Panel(
            Align.center(
                Text(banner_text, style="bold red")
            ),
            box=box.DOUBLE,
            border_style="red",
            title="[bold red] DECEPTICON [/bold red]",
            title_align="center",
            subtitle="[bold cyan] Vibe Hacking Agent [/bold cyan]",
            subtitle_align="center"
        )
        
        
        # 
        info_lines = [
            "[bold magenta]🚀 System Status[/bold magenta]",
            f"├── 🕒 Time: [green]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/green]",
            f"├── 🐍 Python: [yellow]{sys.version.split()[0]}[/yellow]",
            f"├── 💻 Platform: [blue]{sys.platform.upper()}[/blue]",
            "└── 🎯 Mode: [bold magenta]Interactive CLI[/bold magenta]"
        ]
        
        welcome_lines = [
            "[bold magenta]🎮 Available Commands[/bold magenta]",
            "",
            "[green]• help[/green] - Show detailed help guide",
            "[green]• llm[/green] - Show current LLM configuration", 
            "[green]• model-change[/green] - Change LLM model",
            "[green]• mcp-info[/green] - Show MCP tools information",
            "[green]• memory-info[/green] - Show persistence and memory status",
            "[green]• logs[/green] - Show conversation logs and statistics",
            "[green]• clear[/green] - Clear the screen",
            "[green]• quit/exit[/green] - Exit the program",
            "",
            "[cyan]💡 Just type your security requests![/cyan]",
            "[dim]Example: 'Scan 192.168.1.1 with nmap'[/dim]"
        ]

        info_panel = Panel("\n".join(info_lines), box=box.ROUNDED, border_style="cyan", title="[bold cyan]System Information[/bold cyan]", width=60)
        welcome_panel = Panel("\n".join(welcome_lines), box=box.ROUNDED, border_style="green", title="[bold green]Quick Commands[/bold green]", width=60)


        self.console.print()
        self.console.print(banner_panel)
        self.console.print()
        
        columns = Columns([info_panel, welcome_panel], equal=True, expand=True)
        self.console.print(columns)
        self.console.print()
    


    async def display_mcp_infrastructure(self):
        """MCP """
        try:
            self.console.print(Panel(
                "[bold yellow]🚀 Initializing MCP Server[/bold yellow]\n\n"
                "[cyan]Loading MCP tool information...[/cyan]",
                box=box.ROUNDED,
                border_style="yellow",
                title="[bold yellow]🛠️ MCP Server[/bold yellow]"
            ))

            self.tools_config = {}  # 
            root = Tree("[bold cyan]📦 MCP Agents & Tools[/bold cyan]", guide_style="bold bright_blue")

            for agent_name, agent_info in self.agents_config.items():
                agent_node = root.add(f"[bold green]🧠 Agent:[/bold green] {agent_name}")

                if not agent_info.get("servers"):
                    agent_node.add("[dim italic]⚠️  No MCP servers configured[/dim italic]")
                    continue

                for server_name, server_config in agent_info["servers"].items():
                    if "transport" not in server_config:
                        server_config["transport"] = "streamable_http" if "url" in server_config else "stdio"

                    client = MultiServerMCPClient({server_name: server_config})
                    tools = await client.get_tools() if client else []

                    server_node = agent_node.add(f"[bold yellow]🖥️  Server:[/bold yellow] {server_name}")
                    if "url" in server_config:
                        server_node.add(f"[dim]🌐  URL: {server_config['url']}[/dim]")

                    if tools:
                        tools_node = server_node.add("[bold magenta]🧰  Tools[/bold magenta]")
                        for tool in tools:
                            display_name = tool.name.replace("_", " ").title()
                            tools_node.add(f"[white]• {display_name}[/white]")
                            self.tools_config[tool.name] = {
                                "display_name": display_name,
                                "server": server_name,
                                "agent": agent_name,
                            }
                    else:
                        server_node.add("[yellow]⚠️ No tools available (MCP server might be offline)[/yellow]")

            self.console.print(Panel(
                Group(root),
                box=box.ROUNDED,
                border_style="cyan",
                title="[bold cyan]📊 MCP Overview[/bold cyan]"
            ))

        except Exception as e:
            self.console.print(Panel(
                f"[red]❌ MCP Infrastructure Error[/red]\n\n"
                f"[yellow]Error:[/yellow] {str(e)}\n"
                f"[dim]Continuing with available functionality[/dim]",
                box=box.ROUNDED,
                border_style="red",
                title="[bold red]⚠️ MCP Error[/bold red]"
            ))

    
    def display_model_selection(self):
        """LLM """
        self.console.print(Panel(
            "[bold yellow]🤖 LLM Model Selection[/bold yellow]\n\n"
            "[dim]Choose your AI model for red team operations[/dim]",
            box=box.ROUNDED,
            border_style="yellow"
        ))
        
        with Status("[bold green]Loading available models...", console=self.console) as status:
            try:
                models = list_available_models()
                ollama_info = check_ollama_connection()
                status.update("[bold green]Models loaded successfully!")
                time.sleep(0.5)
                
            except Exception as e:
                status.update(f"[bold red]Error loading models: {str(e)}")
                self.console.print(f"[red]❌ Error loading models: {str(e)}[/red]")
                return None
        
        # 
        available_models = [m for m in models if m["api_key_available"]]
        
        if not available_models:
            self.console.print(Panel(
                "[red]❌ No models available[/red]\n\n"
                "[yellow]Setup required:[/yellow]\n"
                "• Set API keys in .env file (OPENAI_API_KEY, ANTHROPIC_API_KEY, etc.)\n"
                "• Or install Ollama from https://ollama.ai/",
                box=box.ROUNDED,
                border_style="red",
                title="Setup Required"
            ))
            return None
        
        # 
        table = Table(
            title="🤖 Available LLM Models",
            box=box.ROUNDED,
            header_style="bold magenta",
            show_lines=True,
            title_style="bold cyan"
        )
        
        table.add_column("ID", style="bold cyan", width=4, justify="center")
        table.add_column("Model Name", style="bold green", width=35)
        table.add_column("Provider", style="bold blue", width=12)
        table.add_column("Status", style="yellow", width=10, justify="center")
        
        # 
        for i, model in enumerate(available_models, 1):
            status_icon = "✅" if model["api_key_available"] else "❌"
            
            table.add_row(
                f"[bold cyan]{i}[/bold cyan]",
                f"[bold]{model['display_name']}[/bold]",
                f"[bold]{model['provider']}[/bold]",
                status_icon
            )
        
        self.console.print(table)
        
        # Ollama 
        if ollama_info["connected"]:
            ollama_panel = Panel(
                f"[green]🟢 Ollama: Running[/green] ({ollama_info['count']} models available)\n"
                f"[cyan]Models:[/cyan] {', '.join(ollama_info['models'][:3])}{'...' if len(ollama_info['models']) > 3 else ''}",
                box=box.ROUNDED,
                border_style="green",
                title="🦙 Ollama Local Models"
            )
            self.console.print(ollama_panel)
        
        # 
        self.console.print()
        while True:
            try:
                choice = Prompt.ask(
                    "[bold cyan]Select model by ID[/bold cyan] [dim](or 'q' to quit)[/dim]",
                    choices=[str(i) for i in range(1, len(available_models) + 1)] + ["q"],
                    default="1"
                )
                
                if choice.lower() == 'q':
                    return None
                
                selected_idx = int(choice) - 1
                selected_model = available_models[selected_idx]
                
                # 
                confirm_panel = Panel(
                    f"[bold green]Selected Model:[/bold green]\n"
                    f"[cyan]• Name:[/cyan] {selected_model['display_name']}\n"
                    f"[cyan]• Provider:[/cyan] {selected_model['provider']}\n"
                    f"[cyan]• Model:[/cyan] {selected_model['model_name']}",
                    box=box.ROUNDED,
                    border_style="green",
                    title="Model Confirmation"
                )
                self.console.print(confirm_panel)
                
                if Confirm.ask("[green]Confirm this selection?[/green]", default=True):
                    return selected_model
                
            except (ValueError, IndexError):
                self.console.print("[red]❌ Invalid selection. Please try again.[/red]")
    
    async def setup_session(self, model_info: Dict[str, Any]):
        """swarm """
        with Status("[bold green]Setting up session...", console=self.console) as status:
            try:
                # Thread configuration (persistence 사용)
                self.config = create_thread_config(
                    user_id=self.user_id,
                    conversation_id="cli_session"
                )
                self.thread_id = self.config["configurable"]["thread_id"]
                
                # 
                self.current_model = model_info
                
                # 
                status.update("[bold green]Updating memory configuration...")
                update_llm_config(
                    model_name=model_info['model_name'],
                    provider=model_info['provider'],
                    display_name=model_info['display_name'],
                    temperature=0.0  # 고정값
                )
                
                # LLM 
                status.update("[bold green]Loading LLM instance...")
                self.current_llm = get_current_llm()
                
                status.update("[bold green]Memory configuration updated!")
                time.sleep(0.5)
                
                #
                model_display_name = model_info.get('display_name', 'Unknown Model') if model_info else 'CLI Model'
                self.logging_session_id = self.logger.start_session(model_display_name)
                
                # swarm 
                status.update("[bold green]Creating AI agents with selected model...")
                self.swarm = await create_dynamic_swarm()
                
                status.update("[bold green]Session setup complete!")
                time.sleep(1)
                
            except Exception as e:
                status.update(f"[bold red]Setup failed: {str(e)}")
                raise
        
        # 
        session_panel = Panel(
            f"[bold green]✅ Session Ready[/bold green]\n\n"
            f"[cyan]🤖 Model:[/cyan] [bold]{self.current_model['display_name']}[/bold]\n"
            f"[cyan]🏢 Provider:[/cyan] [bold]{self.current_model['provider']}[/bold]\n"
            f"[cyan]🆔 Thread:[/cyan] [dim]{self.thread_id[:25]}...[/dim]\n"
            f"[cyan]👤 User ID:[/cyan] [dim]{self.user_id}[/dim]\n"
            f"[cyan]🗋 Memory:[/cyan] [dim]{self.memory_namespace}[/dim]\n"
            f"[cyan]🕒 Started:[/cyan] [bold]{datetime.now().strftime('%H:%M:%S')}[/bold]\n"
            f"[cyan]🤖 Agents:[/cyan] [bold]Dynamically created with persistence[/bold]\n\n"
            f"[yellow]🎯 Ready for red team operations![/yellow]\n"
            f"[dim]All agents will remember your preferences and context[/dim]",
            box=box.ROUNDED,
            border_style="green",
            title="[bold green]🚀 Session Initialized[/bold green]"
        )
        
        self.console.print(session_panel)
    
    def display_current_llm_config(self):
        """LLM """
        try:
            current_config = get_current_llm_config()
            
            config_panel = Panel(
                f"[bold cyan]🤖 Current LLM Configuration[/bold cyan]\n\n"
                f"[cyan]Model:[/cyan] [bold]{current_config.display_name}[/bold]\n"
                f"[cyan]Provider:[/cyan] [bold]{current_config.provider}[/bold]\n"
                f"[cyan]Model Name:[/cyan] [white]{current_config.model_name}[/white]\n"
                f"[cyan]Temperature:[/cyan] [white]0 (fixed)[/white]\n\n"
                f"[green]✅ This model is used by all AI agents[/green]",
                box=box.ROUNDED,
                border_style="cyan",
                title="[bold cyan]🔧 LLM Configuration[/bold cyan]"
            )
            
            self.console.print(config_panel)
            
        except Exception as e:
            self.console.print(Panel(
                f"[red]❌ Error displaying LLM configuration[/red]\n\n"
                f"[yellow]Error:[/yellow] {str(e)}",
                box=box.ROUNDED,
                border_style="red",
                title="Configuration Error"
            ))
    
    async def display_mcp_tools_info(self):
        """MCP """
        try:
            self.console.print("\n[bold cyan]🔧 MCP Tools Information[/bold cyan]\n")
            
            # 
            root = Tree("[bold cyan]MCP Agents & Tools[/bold cyan]")
            
            for agent_name, agent_info in self.agents_config.items():
                agent_node = root.add(f"[bold green]Agent:[/bold green] {agent_name}")
                
                if not agent_info.get("servers"):
                    agent_node.add("[red]No MCP servers configured[/red]")
                    continue
                
                for server_name, server_config in agent_info["servers"].items():
                    server_node = agent_node.add(f"[bold yellow]Server:[/bold yellow] {server_name}")
                    
                    # URL 
                    if "url" in server_config:
                        server_node.add(f"[dim]URL: {server_config['url']}[/dim]")
                    
                    # 
                    if self.tools_config:
                        tools_node = server_node.add("[bold magenta]Available Tools[/bold magenta]")
                        for tool_name, tool_info in self.tools_config.items():
                            tools_node.add(f"[white]  {tool_info['display_name']}[/white]")
                    else:
                        server_node.add("[yellow]No tools loaded yet[/yellow]")
            
            self.console.print(root)
                
        except Exception as e:
            self.console.print(Panel(
                f"[red]❌ Error displaying MCP tools info[/red]\n\n"
                f"[yellow]Error:[/yellow] {str(e)}",
                box=box.ROUNDED,
                border_style="red",
                title="MCP Tools Error"
            ))
            
    def display_memory_info(self):
        """persistence """
        try:
            # Persistence 
            persistence_status = get_persistence_status()
            debug_info = get_debug_info()
            
            # 
            memory_panel = Panel(
                f"[bold cyan]🧠 Memory & Persistence Status[/bold cyan]\n\n"
                f"[cyan]👤 User ID:[/cyan] [bold]{self.user_id}[/bold]\n"
                f"[cyan]🆔 Thread ID:[/cyan] [dim]{self.thread_id[:40] if self.thread_id else 'Not set'}[/dim]\n"
                f"[cyan]🗋 Memory Namespace:[/cyan] [dim]{self.memory_namespace}[/dim]\n\n"
                f"[yellow]📊 Persistence System:[/yellow]\n"
                f"[cyan]  • Checkpointer:[/cyan] [green]✅[/green] {persistence_status.get('checkpointer_type', 'N/A')}\n"
                f"[cyan]  • Store:[/cyan] [green]✅[/green] {persistence_status.get('store_type', 'N/A')}\n"
                f"[cyan]  • Initialized:[/cyan] [green]✅[/green] Both systems ready\n\n"
                f"[yellow]🔧 Current Session:[/yellow]\n"
                f"[cyan]  • Model:[/cyan] [bold]{self.current_model['display_name'] if self.current_model else 'Not set'}[/bold]\n"
                f"[cyan]  • Agents:[/cyan] [bold]{'Ready' if self.swarm else 'Not initialized'}[/bold]\n"
                f"[cyan]  • Conversation Count:[/cyan] [bold]{len(self.conversation_history)}[/bold]\n\n"
                f"[green]📝 Features Available:[/green]\n"
                f"[dim]  • Cross-session memory persistence\n"
                f"  • Agent context sharing\n"
                f"  • Conversation state recovery\n"
                f"  • User preference learning[/dim]",
                box=box.ROUNDED,
                border_style="cyan",
                title="[bold cyan]🧠 Memory System[/bold cyan]"
            )
            
            self.console.print(memory_panel)
            
            # 
            if Confirm.ask("\n[dim]Show detailed debug info?[/dim]", default=False):
                debug_panel = Panel(
                    json.dumps(debug_info, indent=2),
                    box=box.ROUNDED,
                    border_style="yellow",
                    title="[bold yellow]🔍 Debug Information[/bold yellow]"
                )
                self.console.print(debug_panel)
                
        except Exception as e:
            self.console.print(Panel(
                f"[red]❌ Error displaying memory info[/red]\n\n"
                f"[yellow]Error:[/yellow] {str(e)}",
                box=box.ROUNDED,
                border_style="red",
                title="Memory Info Error"
            ))
            
    def display_conversation_logs(self):
        """"""
        try:
            # 
            current_session = self.logger.current_session
            
            if current_session:
                session_panel = Panel(
                    f"[bold cyan]📝 Current Session[/bold cyan]\n\n"
                    f"[cyan]Session ID:[/cyan] [bold]{current_session.session_id[:16]}...[/bold]\n"
                    f"[cyan]Start Time:[/cyan] [bold]{current_session.start_time}[/bold]\n"
                    f"[cyan]Total Events:[/cyan] [bold]{len(current_session.events)}[/bold]\n"
                    f"[cyan]Model:[/cyan] [bold]{current_session.model or 'Unknown'}[/bold]\n\n"
                    f"[green]🟢 Session is actively logging[/green]",
                    box=box.ROUNDED,
                    border_style="cyan",
                    title="[bold cyan]📊 Active Session[/bold cyan]"
                )
                self.console.print(session_panel)
            else:
                self.console.print(Panel(
                    "[yellow]⚠️ No active logging session[/yellow]\n\n"
                    "[dim]Start a conversation to begin logging[/dim]",
                    box=box.ROUNDED,
                    border_style="yellow",
                    title="[bold yellow]📝 Logging Status[/bold yellow]"
                ))
            
            # 
            sessions = self.logger.list_sessions(limit=50)
            
            total_events = sum(s['event_count'] for s in sessions)
            avg_events = total_events / len(sessions) if sessions else 0
            
            stats_panel = Panel(
                f"[bold magenta]📊 Overall Statistics[/bold magenta]\n\n"
                f"[cyan]Total Sessions:[/cyan] [bold]{len(sessions)}[/bold]\n"
                f"[cyan]Total Events:[/cyan] [bold]{total_events}[/bold]\n"
                f"[cyan]Avg Events/Session:[/cyan] [bold]{avg_events:.1f}[/bold]\n\n"
                f"[cyan]Platform:[/cyan] [bold]CLI[/bold]\n"
                f"[cyan]Logging Type:[/cyan] [bold]Minimal (Replay-focused)[/bold]",
                box=box.ROUNDED,
                border_style="magenta",
                title="[bold magenta]📈 User Statistics[/bold magenta]"
            )
            self.console.print(stats_panel)
            
            # 
            recent_sessions = sessions[:10]  # 
            
            if recent_sessions:
                self.console.print(f"\n[bold green]📅 Recent Sessions ({len(recent_sessions)} sessions)[/bold green]\n")
                
                for i, session in enumerate(recent_sessions[:5]):  # 최대 5개만 표시
                    start_time = session['start_time'][:19].replace('T', ' ')
                    
                    session_info = f"💻 [cyan]{start_time}[/cyan] - "
                    session_info += f"[bold]{session['session_id'][:8]}...[/bold] "
                    session_info += f"([blue]{session['event_count']} events[/blue])"
                    
                    if session.get('model'):
                        session_info += f" - [yellow]{session['model']}[/yellow]"
                    
                    if session.get('preview'):
                        session_info += f"\n    [dim]{session['preview']}[/dim]"
                    
                    self.console.print(f"  {i+1}. {session_info}")
                
                if len(recent_sessions) > 5:
                    self.console.print(f"  [dim]... and {len(recent_sessions) - 5} more sessions[/dim]")
            else:
                self.console.print("\n[yellow]📅 No recent sessions found[/yellow]")
            
            # 
            base_path = self.logger.base_path
            self.console.print(f"\n[dim]📁 Logs stored at: {base_path}[/dim]")
            self.console.print(f"[dim]🔄 Replay-compatible logs for Streamlit[/dim]")
            
        except Exception as e:
            self.console.print(Panel(
                f"[red]❌ Error displaying conversation logs[/red]\n\n"
                f"[yellow]Error:[/yellow] {str(e)}",
                box=box.ROUNDED,
                border_style="red",
                title="Logs Error"
            ))
            
    async def change_model(self):
        """"""
        self.console.print(Panel(
            "[bold yellow]🔄 Model Change[/bold yellow]\n\n"
            "[dim]Change your AI model during the session[/dim]",
            box=box.ROUNDED,
            border_style="yellow",
            title="[bold yellow]🤖 Change LLM Model[/bold yellow]"
        ))
        
        # 
        if self.current_model:
            current_panel = Panel(
                f"[cyan]Current Model:[/cyan] [bold]{self.current_model['display_name']}[/bold]\n"
                f"[cyan]Provider:[/cyan] [bold]{self.current_model['provider']}[/bold]",
                box=box.ROUNDED,
                border_style="blue",
                title="[bold blue]📊 Current Model[/bold blue]"
            )
            self.console.print(current_panel)
        
        # 
        new_model_info = self.display_model_selection()
        if not new_model_info:
            self.console.print("[yellow]⚠️ Model change cancelled[/yellow]")
            return False
        
        # 
        if (self.current_model and 
            new_model_info['model_name'] == self.current_model['model_name'] and 
            new_model_info['provider'] == self.current_model['provider']):
            self.console.print(Panel(
                "[yellow]⚠️ Same model selected[/yellow]\n\n"
                "[dim]No changes made[/dim]",
                box=box.ROUNDED,
                border_style="yellow",
                title="No Change"
            ))
            return False
        
        # 
        old_model_name = self.current_model['display_name'] if self.current_model else "Previous Model"
        
        with Status("[bold green]Changing model and recreating agents...", console=self.console) as status:
            try:
                # 
                status.update("[bold green]Updating model configuration...")
                self.current_model = new_model_info
                
                update_llm_config(
                    model_name=new_model_info['model_name'],
                    provider=new_model_info['provider'],
                    display_name=new_model_info['display_name'],
                    temperature=0.0
                )
                
                # LLM 
                status.update("[bold green]Loading new LLM instance...")
                self.current_llm = get_current_llm()
                
                # 
                status.update("[bold green]Recreating AI agents with new model...")
                self.swarm = await create_dynamic_swarm()
                
                # 
                if self.logging_session_id:
                    self.logger.end_session()
                
                model_display_name = new_model_info.get('display_name', 'Unknown Model')
                self.logging_session_id = self.logger.start_session(model_display_name)
                
                status.update("[bold green]Model change completed!")
                time.sleep(1)
                
            except Exception as e:
                status.update(f"[bold red]Model change failed: {str(e)}")
                self.console.print(Panel(
                    f"[bold red]❌ Model Change Failed[/bold red]\n\n"
                    f"[yellow]Error:[/yellow] {str(e)}\n"
                    f"[dim]Keeping previous model[/dim]",
                    box=box.ROUNDED,
                    border_style="red",
                    title="[bold red]⚠️ Error[/bold red]"
                ))
                return False
        
        # 
        success_panel = Panel(
            f"[bold green]✅ Model Changed Successfully[/bold green]\n\n"
            f"[cyan]🆕 From:[/cyan] [dim]{old_model_name}[/dim]\n"
            f"[cyan]🆕 To:[/cyan] [bold]{new_model_info['display_name']}[/bold]\n"
            f"[cyan]🏢 Provider:[/cyan] [bold]{new_model_info['provider']}[/bold]\n\n"
            f"[yellow]🚀 All agents updated with new model![/yellow]",
            box=box.ROUNDED,
            border_style="green",
            title="[bold green]🎉 Model Updated[/bold green]"
        )
        self.console.print(success_panel)
        
        return True
            
    
    def get_user_input_box(self):
        """Rich Prompt.ask를 사용한 기본 입력"""
        
        
        try:
            # Rich  Prompt.ask 
            user_input = Prompt.ask(
                "\n[bold blue]Decepticon > [/bold blue]",  
                console=self.console,
                show_default=False
            )
            
            return user_input.strip()
            
        except (EOFError, KeyboardInterrupt):
            self.console.print("\n[dim yellow]Cancelled[/dim yellow]")
            return None
    
    def display_help(self):
        """도움말 표시"""
        help_content = """
    [bold cyan]📖 Decepticon CLI Help Guide[/bold cyan]

    [yellow]🎯 How to Use:[/yellow]
    Type your penetration testing requests in natural language.
    The AI agents will coordinate to execute your commands.

    [yellow]💡 Example Requests:[/yellow]
    • [green]"Scan 192.168.1.1 with nmap"[/green]
    • [green]"Perform reconnaissance on example.com"[/green]  
    • [green]"Test SSH login with default credentials"[/green]
    • [green]"Check for web vulnerabilities"[/green]

    [yellow]🎮 Special Commands:[/yellow]
    • [green]help[/green] - Show this help guide
    • [green]llm[/green] - Show current LLM configuration
    • [green]model-change[/green] - Change LLM model during session
    • [green]mcp-info[/green] - Show MCP tools information
    • [green]memory-info[/green] - Show persistence and memory status
    • [green]logs[/green] - Show conversation logs and statistics
    • [green]clear[/green] - Clear the screen
    • [green]quit/exit[/green] - Exit the program

    [yellow]🤖 AI Agents:[/yellow]
    Dynamic agents loaded from MCP configuration
        """
        
        help_panel = Panel(
            help_content,
            box=box.ROUNDED,
            border_style="cyan",
            title="[bold cyan]📚 Help & Usage Guide[/bold cyan]"
        )
        
        self.console.print(help_panel)
    
    def should_display_message(self, message, agent_name, step_count):
            """메시지를 표시할지 결정 - 중복 방지"""
            # processed_message_ids 초기화 (없으면 생성)
            if not hasattr(self, 'processed_message_ids'):
                self.processed_message_ids = set()
                
            # 메시지 ID 생성
            message_id = None
            if hasattr(message, 'id') and message.id:
                message_id = message.id
            else:
                content = extract_message_content(message)
                message_id = f"{agent_name}_{hash(content)}"
            
            # 사용자 메시지는 최초 1회만 표시
            if message.__class__.__name__ == 'HumanMessage':
                if message_id not in self.processed_message_ids:
                    self.processed_message_ids.add(message_id)
                    return True, "user"
                return False, None
            
            # AI 메시지는 새로운 것만 표시
            elif message.__class__.__name__ == 'AIMessage':
                if message_id not in self.processed_message_ids:
                    self.processed_message_ids.add(message_id)
                    return True, "ai"
                return False, None
            
            # 도구 메시지는 항상 표시
            elif message.__class__.__name__ == 'ToolMessage':
                if message_id not in self.processed_message_ids:
                    self.processed_message_ids.add(message_id)
                    return True, "tool" 
                return False, None
            
            return False, None



    async def execute_workflow(self, user_input: str):
        """워크플로우 실행"""
        # Swarm이 아직 생성되지 않았는지 확인
        if not self.swarm:
            error_panel = Panel(
                f"[bold red]❌ Swarm not initialized[/bold red]\n\n",
                box=box.ROUNDED,
                border_style="red",
                title="[bold red]⚠️ Initialization Error[/bold red]"
            )
            self.console.print(error_panel)
            return False
            
        self.conversation_history.append(("user", user_input))
        
        # 로깅 - 사용자 입력만 기록
        # workflow_start_time = time.time()
        self.logger.log_user_input(user_input)
        
        # 메시지 ID 추적 초기화 (새로운 워크플로우 시작)
        self.processed_message_ids = set()
        
        inputs = {"messages": [HumanMessage(content=user_input)]}
        
        # 워크플로우 실행
        agent_responses = {}
        step_count = 0
        event_count = 0  # ✅ event_count 초기화 추가

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
            transient=True
        ) as progress:
            main_task = progress.add_task("[bold green]🤖 Working...", total=None)

            try:
                async for namespace, output in self.swarm.astream(
                    inputs,
                    stream_mode="updates",
                    config=self.config if self.config else None,  # type: ignore
                    subgraphs=True
                ):
                    step_count += 1
                    event_count += 1  # ✅ 이벤트 카운트 증가

                    # output이 딕셔너리인지 확인
                    if isinstance(output, dict):
                        for node, value in output.items():
                            # 에이전트 이름 결정
                            agent_name = get_agent_name(namespace)
            
                            # 메시지 처리
                            if "messages" in value and value["messages"]:
                                messages = value["messages"]
                                if messages:
                                    latest_message = messages[-1]
                                    should_display, message_type = self.should_display_message(
                                        latest_message, agent_name, step_count
                                    )
                                    
                                    if should_display:
                                        progress.stop()

                                        if message_type == "ai":
                                            # AI message content 안전 추출
                                            # 로깅용: 원본 텍스트 (이스케이프 안함)
                                            original_content = extract_message_content(latest_message, escape_markup=False)
                                            # Rich 출력용: 이스케이프된 텍스트
                                            safe_content = extract_message_content(latest_message, escape_markup=True)
                                            
                                            # Tool calls 정보 추출
                                            tool_calls = extract_tool_calls(latest_message)
                                            
                                            # 로깅 - 에이전트 응답 (원본 데이터 사용)
                                            self.logger.log_agent_response(
                                                agent_name=agent_name,
                                                content=original_content,
                                                tool_calls=tool_calls if tool_calls else None
                                            )

                                            try:
                                                # 에이전트별 색상 설정
                                                agent_color = AgentManager.get_cli_color(agent_name)
                                                
                                                # Markdown에서 escape 처리 - 안전한 content 사용
                                                content_markdown = Markdown(safe_content)
                                                
                                                # Tool calls가 있으면 추가 정보 표시
                                                if tool_calls:
                                                    # Tool calls 정보를 Rich로 표시
                                                    tool_call_info = []
                                                    for i, tool_call in enumerate(tool_calls, 1):
                                                        tool_name = tool_call.get('name', 'Unknown Tool')
                                                        tool_args = tool_call.get('args', {})
                                                        
                                                        # parse_tool_call 함수로 깔끔한 메시지 생성
                                                        
                                                        tool_call_message = parse_tool_call(tool_call)
                                                        
                                                        tool_call_info.append(f"[bold cyan]{tool_call_message}[/bold cyan]")
                                                        
                                                        # Arguments가 있으면 세부 정보 추가
                                                        if tool_args:
                                                            args_str = ", ".join([f"{k}={v}" for k, v in tool_args.items()])
                                                            if len(args_str) > 100:  # 너무 길면 자르기
                                                                args_str = args_str[:100] + "..."
                                                            tool_call_info.append(f"  [dim]→ {args_str}[/dim]")
                                                    
                                                    # Content와 tool calls를 합쳐서 표시
                                                    if original_content.strip():  # content가 있는 경우
                                                        combined_content = Group(
                                                            content_markdown,
                                                            "\n".join(tool_call_info)
                                                        )
                                                    else:  # content가 비어있는 경우
                                                        combined_content = "\n".join(tool_call_info)
                                                    
                                                    agent_panel = Panel(
                                                        combined_content,
                                                        box=box.ROUNDED,
                                                        border_style=agent_color,
                                                        title=f"[{agent_color} bold]{agent_name}[/{agent_color} bold]"
                                                    )
                                                else:
                                                    # Tool calls가 없으면 기존 방식
                                                    agent_panel = Panel(
                                                        content_markdown,
                                                        box=box.ROUNDED,
                                                        border_style=agent_color,
                                                        title=f"[{agent_color} bold]{agent_name}[/{agent_color} bold]"
                                                    )
                                                
                                                self.console.print(agent_panel)
                                            except Exception as panel_error:
                                                # Panel 출력 실패 시 기본 출력 (안전한 텍스트 사용)
                                                self.console.print(f"[{agent_name}]: {safe_content}")

                                            if agent_name not in agent_responses:
                                                agent_responses[agent_name] = []
                                            agent_responses[agent_name].append(safe_content)

                                        elif message_type == "tool":
                                            # Tool message content 안전 추출 
                                            # 로깅용: 원본 텍스트 (이스케이프 안함)
                                            original_content = extract_message_content(latest_message, escape_markup=False)
                                            # Rich 출력용: 이스케이프된 텍스트
                                            safe_content = extract_message_content(latest_message, escape_markup=True)
                                            
                                            tool_name = getattr(latest_message, 'name', 'Unknown Tool')
                                            tool_display_name = parse_tool_name(tool_name)
                                            
                                            # 로깅 - 도구 출력 (원본 데이터 사용)
                                            self.logger.log_tool_output(
                                                tool_name=tool_name,
                                                output=original_content
                                            )

                                            # 도구는 녹색으로 고정
                                            tool_color = "green"
                                            
                                            try:
                                                tool_panel = Panel(
                                                    safe_content,  # 이스케이프된 컨텐트
                                                    box=box.ROUNDED,
                                                    border_style=tool_color,
                                                    title=f"[bold {tool_color}]{tool_display_name}[/bold {tool_color}]"
                                                )
                                                self.console.print(tool_panel)
                                            except Exception as panel_error:
                                                # Panel 출력 실패 시 기본 출력 (안전한 텍스트 사용)
                                                fallback_output = f"[{tool_display_name}]: {safe_content}"
                                                self.console.print(fallback_output)
                                            

                                    # 진행 상황 재시작
                                    progress.start()
                                    progress.update(main_task, description=f"[bold blue]🤖 Working... [/bold blue]")

                # 워크플로우 완료 후 완료 상태 표시
                progress.update(main_task, description="[bold green]✅ Workflow completed!")
                time.sleep(1)
                progress.stop()
                
                # 로깅 - 세션 자동 저장
                self.logger.save_session()

                # 완료 요약
                completion_panel = Panel(
                    f"[bold green]✅ Operation Completed[/bold green]\n\n"
                    f"[cyan]📊 Agents:[/cyan] {', '.join(agent_responses.keys())}\n"
                    f"[cyan]📝 Responses:[/cyan] {sum(len(responses) for responses in agent_responses.values())}\n"
                    f"[cyan]🔄 Steps:[/cyan] {step_count}\n"
                    f"[cyan]🕒 Time:[/cyan] {datetime.now().strftime('%H:%M:%S')}",
                    box=box.ROUNDED,
                    border_style="green",
                    title="[bold green]🎉 Success[/bold green]"
                )
                self.console.print(completion_panel)

                return True

            except Exception as e:
                progress.update(main_task, description=f"[bold red]❌ Error: {str(e)}")
                time.sleep(2)
                progress.stop()
                
                # 로깅 - 세션 저장 시도
                try:
                    self.logger.save_session()
                except Exception as log_error:
                    self.console.print(f"[yellow]Warning: Failed to save session: {log_error}[/yellow]")

                error_panel = Panel(
                    f"[bold red]❌ Workflow Error[/bold red]\n\n"
                    f"[yellow]Error:[/yellow] {str(e)}\n"
                    f"[yellow]Events processed:[/yellow] {event_count if 'event_count' in locals() else 'Unknown'}\n"
                    f"[dim]Please try again[/dim]",
                    box=box.ROUNDED,
                    border_style="red",
                    title="[bold red]⚠️ Error[/bold red]"
                )
                self.console.print(error_panel)
                return False

    
    async def interactive_session(self):
        """대화형 세션"""
        start_panel = Panel(
            f"[bold green]🚀 Interactive Session Started[/bold green]\n\n"
            f"[cyan]🎯 Ready for red team operations[/cyan]\n"
            f"[cyan]💡 Type your requests in natural language[/cyan]\n"
            f"[cyan]❓ Use 'help' for guidance[/cyan]\n\n"
            f"[yellow]Model:[/yellow] [bold]{self.current_model['display_name'] if self.current_model else 'Not set'}[/bold]",
            box=box.ROUNDED,
            border_style="green",
            title="[bold green]🎮 Interactive Mode[/bold green]"
        )
        
        self.console.print(start_panel)
        
        while True:
            try:
                # 사각형 상자 스타일의 입력 받기
                self.console.print("\n")  # 공백 추가
                user_input = self.get_user_input_box()
                
                # 입력이 None인 경우 (Ctrl+C 등)
                if user_input is None:
                    if Confirm.ask("\n[yellow]Exit Decepticon?[/yellow]"):
                        break
                    continue
                
                if not user_input:
                    continue
                
                # 특수 명령어 처리
                if user_input.lower() in ['quit', 'exit', 'q']:
                    if Confirm.ask("\n[yellow]Exit Decepticon?[/yellow]"):
                        break
                elif user_input.lower() == 'help':
                    self.display_help()
                elif user_input.lower() == 'llm':
                    self.display_current_llm_config()
                elif user_input.lower() in ['model-change', 'change-model']:
                    await self.change_model()
                elif user_input.lower() == 'mcp-info':
                    await self.display_mcp_tools_info()
                elif user_input.lower() in ['memory-info', 'memory']:
                    self.display_memory_info()
                elif user_input.lower() in ['logs', 'log-info', 'conversation-logs']:
                    self.display_conversation_logs()
                elif user_input.lower() == 'clear':
                    self.console.clear()
                    self.display_banner()
                else:
                    # 워크플로우 실행
                    await self.execute_workflow(user_input)
                    
            except KeyboardInterrupt:
                self.console.print("\n[yellow]⚠️ Interrupted by user[/yellow]")
                if Confirm.ask("[yellow]Exit Decepticon?[/yellow]"):
                    break
            except Exception as e:
                error_panel = Panel(
                    f"[bold red]❌ Session Error[/bold red]\n\n"
                    f"[yellow]Error:[/yellow] {str(e)}",
                    box=box.ROUNDED,
                    border_style="red",
                    title="Error"
                )
                self.console.print(error_panel)
        
        # 종료 메시지
        farewell_panel = Panel(
            "[bold cyan]👋 Thank you for using Decepticon![/bold cyan]\n\n"
            "[green]🛡️ Stay secure and happy hacking![/green]",
            box=box.ROUNDED,
            border_style="cyan",
            title="[bold cyan]🎉 Session Complete[/bold cyan]"
        )
        self.console.print(farewell_panel)
    
    async def run(self):
        """메인 실행 함수"""
        try:
            # 1. 배너 표시
            self.display_banner()
            
            # 2. MCP 인프라 정보 표시
            await self.display_mcp_infrastructure()
            
            # 3. LLM 모델 선택
            model_info = self.display_model_selection()
            if not model_info:
                self.console.print(Panel(
                    "[red]❌ No model selected[/red]\n\n"
                    "[yellow]Decepticon requires an AI model to function.[/yellow]",
                    box=box.ROUNDED,
                    border_style="red",
                    title="Startup Failed"
                ))
                return
            
            # 4. 세션 설정
            await self.setup_session(model_info)
            
            # 5. 대화형 세션 시작
            await self.interactive_session()
            
        except KeyboardInterrupt:
            self.console.print("\n[yellow]⚠️ Program interrupted[/yellow]")
        except Exception as e:
            error_panel = Panel(
                f"[bold red]❌ Fatal Error[/bold red]\n\n"
                f"[yellow]Error:[/yellow] {str(e)}",
                box=box.ROUNDED,
                border_style="red",
                title="Fatal Error"
            )
            self.console.print(error_panel)


async def main():
    """메인 엔트리 포인트"""
    try:
        cli = DecepticonCLI()
        await cli.run()
    except ImportError as e:
        console.print(Panel(
            f"[bold red]❌ Import Error[/bold red]\n\n"
            f"[yellow]Missing dependency:[/yellow] {str(e)}\n\n"
            f"[cyan]Solutions:[/cyan]\n"
            f"• Run from project root directory\n"
            f"• Install dependencies: [green]pip install -e .[/green]",
            box=box.ROUNDED,
            border_style="red",
            title="Setup Error"
        ))
    except Exception as e:
        console.print(Panel(
            f"[bold red]❌ Startup Error[/bold red]\n\n"
            f"[yellow]Error:[/yellow] {str(e)}",
            box=box.ROUNDED,
            border_style="red",
            title="Startup Failed"
        ))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[bold cyan]👋 Goodbye![/bold cyan]")
    except Exception as e:
        try:
            # 안전한 에러 출력
            error_msg = markup.escape(str(e))
            console.print(f"[bold red]❌ Critical Error: {error_msg}[/bold red]")
        except:
            # Rich도 실패하면 기본 print 사용
            print(f"Critical Error: {str(e)}")