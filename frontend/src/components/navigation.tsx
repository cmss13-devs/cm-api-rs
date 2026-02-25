import { useState, useRef, useEffect } from "react";
import { Link } from "react-router-dom";
import { LinkColor } from "./link";
import { NameExpand } from "./nameExpand";
import type { User } from "../types/global";

interface NavDropdownProps {
  label: string;
  children: React.ReactNode;
}

function NavDropdown({ label, children }: NavDropdownProps) {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  return (
    <div className="relative" ref={dropdownRef}>
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className="text-cyan-400 hover:text-cyan-300 hover:underline flex items-center gap-1"
      >
        {label}
        <svg
          className={`w-3 h-3 transition-transform ${isOpen ? "rotate-180" : ""}`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {isOpen && (
        <div className="absolute top-full left-0 mt-1 py-1 min-w-[150px] foreground border border-gray-600 rounded shadow-lg z-50">
          {children}
        </div>
      )}
    </div>
  );
}

interface NavDropdownItemProps {
  to: string;
  children: React.ReactNode;
  onClick?: () => void;
}

function NavDropdownItem({ to, children, onClick }: NavDropdownItemProps) {
  return (
    <Link
      to={to}
      onClick={onClick}
      className="block px-3 py-1.5 text-cyan-400 hover:text-cyan-300 hover:bg-gray-700/50"
    >
      {children}
    </Link>
  );
}

interface NavigationProps {
  user: User | undefined;
  onLogout: () => void;
}

export function Navigation({ user, onLogout }: NavigationProps) {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const closeMobileMenu = () => setMobileMenuOpen(false);

  return (
    <nav className="w-full foreground p-3">
      {/* Desktop Navigation */}
      <div className="hidden md:flex flex-row items-center gap-3">
        <LinkColor>
          <Link to="/" className="underline font-bold">
            [cmdb]
          </Link>
        </LinkColor>

        <span className="text-gray-500">|</span>

        {/* Players Dropdown */}
        <NavDropdown label="Players">
          <NavDropdownItem to="/bans">Active Bans</NavDropdownItem>
          <NavDropdownItem to="/ban-history">Ban History</NavDropdownItem>
          {user?.isStaff && (
            <>
              <NavDropdownItem to="/user">User Lookup</NavDropdownItem>
              <NavDropdownItem to="/new_players">New Players</NavDropdownItem>
              <NavDropdownItem to="/whitelists">Whitelists</NavDropdownItem>
            </>
          )}
        </NavDropdown>

        {user?.isStaff && (
          <>
            <span className="text-gray-500">|</span>

            {/* Admin Tools Dropdown */}
            <NavDropdown label="Admin">
              <NavDropdownItem to="/ticket">Tickets</NavDropdownItem>
              <NavDropdownItem to="/sticky">Stickybans</NavDropdownItem>
              <NavDropdownItem to="/authentik">Authentik</NavDropdownItem>
            </NavDropdown>
          </>
        )}

        {user?.manageable?.length ? (
          <>
            <span className="text-gray-500">|</span>
            <LinkColor>
              <Link to="/user_manager">User Manager</Link>
            </LinkColor>
          </>
        ) : null}

        {/* User section - pushed to right */}
        {user && (
          <div className="ml-auto flex items-center gap-3">
            <span className="text-gray-400">
              {user.username} (
              {user.isStaff ? <NameExpand name={user.ckey} /> : user.ckey}
              )
            </span>
            <LinkColor>
              <Link to="/account">Account</Link>
            </LinkColor>
            <button
              type="button"
              onClick={onLogout}
              className="text-red-400 hover:text-red-300 hover:underline"
            >
              Logout
            </button>
          </div>
        )}
      </div>

      {/* Mobile Navigation */}
      <div className="md:hidden flex items-center justify-between">
        <LinkColor>
          <Link to="/" className="underline font-bold">
            [cmdb]
          </Link>
        </LinkColor>

        <button
          type="button"
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          className="text-gray-400 hover:text-white p-1"
          aria-label="Toggle menu"
        >
          {mobileMenuOpen ? (
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          ) : (
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
            </svg>
          )}
        </button>
      </div>

      {/* Mobile Menu */}
      {mobileMenuOpen && (
        <div className="md:hidden mt-3 pt-3 border-t border-gray-600 flex flex-col gap-2">
          {user && (
            <div className="text-gray-400 text-sm pb-2 border-b border-gray-700">
              {user.username} ({user.ckey})
            </div>
          )}

          <div className="text-gray-500 text-xs uppercase mt-2">Players</div>
          <Link to="/bans" onClick={closeMobileMenu} className="text-cyan-400 hover:text-cyan-300 pl-2">
            Active Bans
          </Link>
          <Link to="/ban-history" onClick={closeMobileMenu} className="text-cyan-400 hover:text-cyan-300 pl-2">
            Ban History
          </Link>
          {user?.isStaff && (
            <>
              <Link to="/user" onClick={closeMobileMenu} className="text-cyan-400 hover:text-cyan-300 pl-2">
                User Lookup
              </Link>
              <Link to="/new_players" onClick={closeMobileMenu} className="text-cyan-400 hover:text-cyan-300 pl-2">
                New Players
              </Link>
              <Link to="/whitelists" onClick={closeMobileMenu} className="text-cyan-400 hover:text-cyan-300 pl-2">
                Whitelists
              </Link>
            </>
          )}

          {user?.isStaff && (
            <>
              <div className="text-gray-500 text-xs uppercase mt-3">Admin</div>
              <Link to="/ticket" onClick={closeMobileMenu} className="text-cyan-400 hover:text-cyan-300 pl-2">
                Tickets
              </Link>
              <Link to="/sticky" onClick={closeMobileMenu} className="text-cyan-400 hover:text-cyan-300 pl-2">
                Stickybans
              </Link>
              <Link to="/authentik" onClick={closeMobileMenu} className="text-cyan-400 hover:text-cyan-300 pl-2">
                Authentik
              </Link>
            </>
          )}

          {user?.manageable?.length ? (
            <>
              <div className="text-gray-500 text-xs uppercase mt-3">Management</div>
              <Link to="/user_manager" onClick={closeMobileMenu} className="text-cyan-400 hover:text-cyan-300 pl-2">
                User Manager
              </Link>
            </>
          ) : null}

          {user && (
            <>
              <div className="text-gray-500 text-xs uppercase mt-3">Account</div>
              <Link to="/account" onClick={closeMobileMenu} className="text-cyan-400 hover:text-cyan-300 pl-2">
                Settings
              </Link>
              <button
                type="button"
                onClick={() => {
                  closeMobileMenu();
                  onLogout();
                }}
                className="text-red-400 hover:text-red-300 text-left pl-2"
              >
                Logout
              </button>
            </>
          )}
        </div>
      )}
    </nav>
  );
}
